package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/metril/certforge/internal/settings"
)

// ErrNotConfigured is returned by Provider.Client when the "vault" settings
// section has no address set.
var ErrNotConfigured = errors.New("vault: not configured")

// settingsSource is what Provider needs from *settings.Store: the section's
// current effective public value and its decrypted secrets, both read live
// (so a settings change is picked up without a restart). Kept as an
// interface, not *settings.Store directly, so provider_test.go can exercise
// Provider without a database.
type settingsSource interface {
	GetSection(ctx context.Context, sec *settings.Section) (value, stored json.RawMessage, err error)
	SectionSecrets(ctx context.Context, sec *settings.Section) (map[string]string, error)
}

// TestResult is testVaultSettings' outcome (Shared contract VaultTestResult).
type TestResult struct {
	OK              bool
	TokenTTLSeconds int
	Policies        []string
	Version         string
	Error           string
}

// Provider builds a live *Client from the "vault" settings section. Client
// caches the result, keyed by a SHA-256 hash of the section's effective
// value plus its decrypted secrets, and closes the previous client's
// renewal loop whenever the hash changes. Test builds a separate, throwaway
// client against a candidate value and never touches the cache.
type Provider struct {
	store settingsSource
	sec   *settings.Section

	mu     sync.Mutex
	hash   string
	client *Client
}

// NewProvider returns a Provider backed by store, using sections' "vault"
// section (RegisterSettings must have already added it).
func NewProvider(store *settings.Store, sections *settings.Registry) *Provider {
	sec, ok := sections.Section(SectionName)
	if !ok {
		panic("vault: settings section not registered; call vault.RegisterSettings first")
	}
	return &Provider{store: store, sec: sec}
}

// resolved reads the section's current effective Settings (public value
// plus decrypted secrets merged in) and a stable hash over that combined
// value, used both to decide whether Client's cache is still fresh and as
// the material Client itself is built from.
func (p *Provider) resolved(ctx context.Context) (Settings, string, error) {
	value, _, err := p.store.GetSection(ctx, p.sec)
	if err != nil {
		return Settings{}, "", err
	}
	var s Settings
	if err := json.Unmarshal(value, &s); err != nil {
		return Settings{}, "", err
	}
	secrets, err := p.store.SectionSecrets(ctx, p.sec)
	if err != nil {
		return Settings{}, "", err
	}
	s.Token = secrets["token"]
	s.SecretID = secrets["secretId"]

	canon, err := json.Marshal(s)
	if err != nil {
		return Settings{}, "", err
	}
	sum := sha256.Sum256(canon)
	return s, hex.EncodeToString(sum[:]), nil
}

// Configured reports whether the "vault" section currently has an address
// set (Shared contract: readiness's checks.vault only appears with one, and
// a vaultpki CA cannot be created without one).
func (p *Provider) Configured(ctx context.Context) bool {
	s, _, err := p.resolved(ctx)
	return err == nil && s.Address != ""
}

// Client returns the current live client for the "vault" section, building
// (and logging in) a fresh one only when the section's resolved value has
// changed since the last call; otherwise the cached client is reused. The
// returned client's renewal loop runs detached from ctx (context.Background
// internally), so it keeps renewing for as long as the Provider itself
// lives, not just for the duration of this call; a client this Client
// replaces has its own loop stopped via Close.
func (p *Provider) Client(ctx context.Context) (*Client, error) {
	s, hash, err := p.resolved(ctx)
	if err != nil {
		return nil, err
	}
	if s.Address == "" {
		return nil, ErrNotConfigured
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client != nil && p.hash == hash {
		return p.client, nil
	}

	c, err := clientFromSettings(s)
	if err != nil {
		return nil, err
	}
	if err := c.Login(ctx); err != nil {
		return nil, c.Redact(err)
	}
	c.Start(context.Background())

	old := p.client
	p.client, p.hash = c, hash
	if old != nil {
		old.Close()
	}
	return c, nil
}

// Test builds a throwaway client from raw (a candidate "vault" section
// value, as sent to PUT /settings/vault or POST /settings/vault/test) and
// reports whether it can log in and look up its own token. raw's secret
// fields ("" or "__unchanged__"/omitted) are merged with the section's
// currently stored secrets first — callers must have already run
// p.sec.ValidateUpdate (the re-entry rule) before calling Test, since a
// merge is only safe once that has passed. A connection or auth failure is
// reported as TestResult{OK: false}, not an error: the request itself was
// well-formed, Vault just did not answer the way it was asked to.
func (p *Provider) Test(ctx context.Context, raw json.RawMessage) TestResult {
	var s Settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return TestResult{OK: false, Error: err.Error()}
	}
	secrets, err := p.store.SectionSecrets(ctx, p.sec)
	if err != nil {
		return TestResult{OK: false, Error: err.Error()}
	}
	if s.Token == "" || s.Token == settings.Unchanged {
		s.Token = secrets["token"]
	}
	if s.SecretID == "" || s.SecretID == settings.Unchanged {
		s.SecretID = secrets["secretId"]
	}

	c, err := clientFromSettings(s)
	if err != nil {
		return TestResult{OK: false, Error: scrubRaw(err.Error(), raw)}
	}
	if err := c.Login(ctx); err != nil {
		return TestResult{OK: false, Error: scrubRaw(c.Redact(err).Error(), raw)}
	}
	health, err := c.Health(ctx)
	if err != nil {
		return TestResult{OK: false, Error: scrubRaw(c.Redact(err).Error(), raw)}
	}
	info, err := c.LookupSelf(ctx)
	if err != nil {
		return TestResult{OK: false, Error: scrubRaw(c.Redact(err).Error(), raw)}
	}
	return TestResult{OK: true, TokenTTLSeconds: int(info.TTL.Seconds()), Policies: info.Policies, Version: health.Version}
}

// clientFromSettings builds (but does not log in) a *Client from a
// resolved Settings value.
func clientFromSettings(s Settings) (*Client, error) {
	var auth Auth
	method := s.AuthMethod
	if method == "" {
		method = "token"
	}
	switch method {
	case "approle":
		auth = AppRoleAuth{RoleID: s.RoleID, SecretID: s.SecretID}
	default:
		auth = TokenAuth{Token: s.Token}
	}
	cfg := Config{Addr: s.Address, Namespace: s.Namespace, CAPEM: s.CAPem, Auth: auth}
	if s.TimeoutSeconds > 0 {
		cfg.Timeout = time.Duration(s.TimeoutSeconds) * time.Second
	}
	return New(cfg)
}
