package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/metril/certforge/internal/settings"
)

// SettingsSection is the settings section holding OIDC, session and proxy config.
const SettingsSection = "authentication"

const authSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "enabled": {"type": "boolean", "title": "Single sign-on", "description": "Show the single sign-on button on the login page.", "default": false},
    "issuer": {"type": "string", "title": "Issuer URL", "description": "The OIDC issuer; CertForge reads its discovery document.", "pattern": "^https?://[^\\s]+$", "examples": ["https://login.example.com/realms/main"]},
    "clientId": {"type": "string", "title": "Client ID", "description": "The client registered for CertForge at the identity provider.", "maxLength": 200, "examples": ["certforge"]},
    "clientSecret": {"type": "string", "title": "Client secret", "description": "Leave empty for a public client using PKCE only.", "secret": true, "maxLength": 1024},
    "scopes": {"type": "array", "title": "Scopes", "description": "Requested scopes; must include openid.", "items": {"type": "string"}, "default": ["openid", "profile", "email", "groups"]},
    "groupsClaim": {"type": "string", "title": "Groups claim", "description": "ID token claim listing the user's groups; group role bindings match these.", "default": "groups", "maxLength": 128},
    "sessionTtlHours": {"type": "integer", "title": "Session lifetime (hours)", "description": "How long a sign-in lasts. Applies to new sessions.", "minimum": 1, "maximum": 720, "default": 12},
    "trustedProxies": {"type": "array", "title": "Trusted proxies", "description": "Addresses or CIDRs of reverse proxies whose X-Forwarded-For is believed.", "items": {"type": "string"}, "default": [], "examples": [["10.0.0.0/8"]]},
    "loginRatePerMinute": {"type": "integer", "title": "Login rate limit (per minute)", "description": "Login attempts allowed per client address per minute. 0 disables the limit.", "minimum": 0, "default": 10},
    "loginBurst": {"type": "integer", "title": "Login rate limit burst", "description": "Login attempts a client may make in a single burst before the per-minute rate applies.", "minimum": 1, "default": 5}
  }
}`

const authDefault = `{"enabled":false,"scopes":["openid","profile","email","groups"],"groupsClaim":"groups","sessionTtlHours":12,"trustedProxies":[],"loginRatePerMinute":10,"loginBurst":5}`

// AuthSettings is the decoded authentication section plus its secret.
type AuthSettings struct {
	Enabled         bool     `json:"enabled"`
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"clientId"`
	Scopes          []string `json:"scopes"`
	GroupsClaim     string   `json:"groupsClaim"`
	SessionTTLHours int      `json:"sessionTtlHours"`
	TrustedProxies  []string `json:"trustedProxies"`
	// LoginRatePerMinute is the per-client login attempt limit; <= 0 disables
	// the limit (matches Limiter's own semantics).
	LoginRatePerMinute int    `json:"loginRatePerMinute"`
	LoginBurst         int    `json:"loginBurst"`
	ClientSecret       string `json:"-"`
	proxies            []netip.Prefix
}

// LogValue redacts ClientSecret so AuthSettings is safe to log.
func (s AuthSettings) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("enabled", s.Enabled),
		slog.String("issuer", s.Issuer),
		slog.String("clientId", s.ClientID),
		slog.Int("sessionTtlHours", s.SessionTTLHours),
		slog.Int("loginRatePerMinute", s.LoginRatePerMinute),
		slog.Int("loginBurst", s.LoginBurst),
	)
}

// String redacts ClientSecret so AuthSettings is safe to print or interpolate.
func (s AuthSettings) String() string {
	return fmt.Sprintf("AuthSettings{Enabled:%v Issuer:%q ClientID:%q ClientSecret:REDACTED SessionTTLHours:%d LoginRatePerMinute:%d LoginBurst:%d}",
		s.Enabled, s.Issuer, s.ClientID, s.SessionTTLHours, s.LoginRatePerMinute, s.LoginBurst)
}

// RegisterSettings adds the authentication section and its extra checks.
func RegisterSettings(r *settings.Registry) error {
	if err := r.Register(SettingsSection, json.RawMessage(authSchema), json.RawMessage(authDefault)); err != nil {
		return err
	}
	return r.AddCheck(SettingsSection, checkAuthSettings)
}

func checkAuthSettings(raw json.RawMessage) error {
	var s AuthSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	if _, err := parseProxies(s.TrustedProxies); err != nil {
		return err
	}
	if s.Enabled && (s.Issuer == "" || s.ClientID == "") {
		return errors.New("issuer and clientId are required when single sign-on is enabled")
	}
	if len(s.Scopes) > 0 && !slices.Contains(s.Scopes, "openid") {
		return errors.New("scopes must include openid")
	}
	return nil
}

func parseProxies(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("trustedProxies: %q is not an IP address or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func (s *AuthSettings) normalize() {
	if len(s.Scopes) == 0 {
		s.Scopes = []string{"openid", "profile", "email", "groups"}
	}
	if s.GroupsClaim == "" {
		s.GroupsClaim = "groups"
	}
	switch {
	case s.SessionTTLHours <= 0:
		s.SessionTTLHours = int(DefaultSessionTTL / time.Hour)
	case s.SessionTTLHours > 720:
		s.SessionTTLHours = 720
	}
	if s.LoginBurst <= 0 {
		// A zero burst would reject every login outright; only the rate
		// itself (LoginRatePerMinute) is allowed to mean "unlimited".
		s.LoginBurst = DefaultLoginBurst
	}
	s.proxies, _ = parseProxies(s.TrustedProxies)
}

// OIDCReady reports whether single sign-on is enabled and configured.
func (s AuthSettings) OIDCReady() bool { return s.Enabled && s.Issuer != "" && s.ClientID != "" }

// SessionTTL is the lifetime of new sessions.
func (s AuthSettings) SessionTTL() time.Duration { return time.Duration(s.SessionTTLHours) * time.Hour }

// RemoteIP is the request's socket peer address without the port.
func RemoteIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// ClientIP returns the client address. X-Forwarded-For is believed only when
// the peer is a trusted proxy; the walk goes right to left over trusted hops
// and returns the first untrusted one, so a client cannot prepend a fake hop.
func (s AuthSettings) ClientIP(r *http.Request) string {
	remote := RemoteIP(r)
	addr, err := netip.ParseAddr(remote)
	if err != nil {
		return remote
	}
	addr = addr.Unmap()
	if !s.trusted(addr) {
		return addr.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hops = append(hops, h)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil {
			return addr.String()
		}
		a = a.Unmap()
		if !s.trusted(a) {
			return a.String()
		}
		addr = a
	}
	return addr.String()
}

// TrustedProxy reports whether r's TCP peer is one of the configured
// trusted proxies, for callers (such as the cookie Secure flag) that need to
// know whether X-Forwarded-Proto from this request can be believed.
func (s AuthSettings) TrustedProxy(r *http.Request) bool {
	addr, err := netip.ParseAddr(RemoteIP(r))
	if err != nil {
		return false
	}
	return s.trusted(addr)
}

func (s AuthSettings) trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// SettingsSource caches the authentication section for 30 s. PUT
// /settings/authentication calls Invalidate.
type SettingsSource struct {
	store *settings.Store
	sec   *settings.Section
	ttl   time.Duration
	now   func() time.Time
	mu    sync.Mutex
	cur   AuthSettings
	at    time.Time
	valid bool
}

// NewSettingsSource reads the registered authentication section from store.
func NewSettingsSource(store *settings.Store, reg *settings.Registry) (*SettingsSource, error) {
	sec, ok := reg.Section(SettingsSection)
	if !ok {
		return nil, errors.New("authn: authentication settings section not registered")
	}
	return &SettingsSource{store: store, sec: sec, ttl: 30 * time.Second, now: time.Now}, nil
}

// Get returns the current settings, reloading after the cache expires.
func (s *SettingsSource) Get(ctx context.Context) (AuthSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.valid && s.now().Sub(s.at) < s.ttl {
		return s.cur, nil
	}
	raw, _, err := s.store.GetSection(ctx, s.sec)
	if err != nil {
		return AuthSettings{}, err
	}
	var st AuthSettings
	if err := json.Unmarshal(raw, &st); err != nil {
		return AuthSettings{}, fmt.Errorf("authn: decode settings: %w", err)
	}
	secrets, err := s.store.SectionSecrets(ctx, s.sec)
	if err != nil {
		return AuthSettings{}, err
	}
	st.ClientSecret = secrets["clientSecret"]
	st.normalize()
	s.cur, s.at, s.valid = st, s.now(), true
	return st, nil
}

// Invalidate drops the cached settings.
func (s *SettingsSource) Invalidate() {
	s.mu.Lock()
	s.valid = false
	s.mu.Unlock()
}
