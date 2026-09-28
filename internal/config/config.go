// Package config loads the bootstrap settings CertForge needs before it can
// reach and decrypt its database. Everything else lives in the settings table.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
)

// KEKSize is the required key-encryption-key length in bytes.
const KEKSize = 32

// KEK kinds.
const (
	KEKKindStatic       = "static"
	KEKKindVaultTransit = "vault-transit"
)

// KEKConfig is the active key-encryption key: a 32-byte static key held
// directly (Kind static, Key set) or a Vault Transit key reached over the
// network (Kind vault-transit, Vault set).
type KEKConfig struct {
	// Kind is KEKKindStatic or KEKKindVaultTransit.
	Kind string
	// Source names which CF_KEK* variable supplied it ("env", "file" or
	// "vault"), for logging only: never the key material itself.
	Source string
	// Key is the 32-byte static KEK. Empty for vault-transit.
	Key []byte
	// Vault configures the Transit-backed KEK. Nil for static.
	Vault *VaultKEK
}

// VaultKEK configures a Transit-backed KEK.
type VaultKEK struct {
	Addr string
	// Mount is the Transit secrets engine mount (default "transit").
	Mount string
	// Key is the Transit key name (CF_KEK_VAULT_TRANSIT_KEY), not key
	// material: Vault holds the actual key and never gives it out.
	Key       string
	Namespace string
	// CAFile is CF_KEK_VAULT_CA_FILE's contents (PEM), read at Load, not
	// the path itself, despite the name matching the env var it comes from.
	CAFile string
	// Token is the Vault token (CF_KEK_VAULT_TOKEN or ..._FILE). Empty
	// unless token auth is used.
	Token string
	// RoleID and SecretID are AppRole credentials (CF_KEK_VAULT_ROLE_ID and
	// CF_KEK_VAULT_SECRET_ID or ..._FILE). Empty unless AppRole auth is used.
	RoleID   string
	SecretID string
}

// Config is the bootstrap configuration read from CF_* environment variables.
type Config struct {
	DatabaseURL string
	KEK         KEKConfig
	// PreviousKEKs are KEKs a rotation moved away from, still configured so
	// the multi-wrapper crypto.Envelope can decrypt not-yet-rewrapped data
	// and internal/kek.RewrapWorker can move it onto KEK. At most one
	// static (CF_KEK_PREVIOUS[_FILE]) and one vault-transit
	// (CF_KEK_PREVIOUS_VAULT_*) entry, in that order when both are set.
	PreviousKEKs []KEKConfig
	ListenHTTP   string
	ListenAgent  string
	BaseURL      string
	LogLevel     string
}

// Load reads and validates the CF_* environment variables.
func Load() (Config, error) {
	c := Config{
		DatabaseURL: strings.TrimSpace(os.Getenv("CF_DATABASE_URL")),
		ListenHTTP:  envOr("CF_LISTEN_HTTP", ":8080"),
		ListenAgent: envOr("CF_LISTEN_AGENT", ":8443"),
		BaseURL:     strings.TrimRight(strings.TrimSpace(os.Getenv("CF_BASE_URL")), "/"),
		LogLevel:    strings.ToLower(envOr("CF_LOG_LEVEL", "info")),
	}
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("CF_DATABASE_URL is required"))
	}
	kek, err := loadKEK()
	if err != nil {
		errs = append(errs, err)
	} else {
		c.KEK = kek
	}
	prev, err := loadPreviousKEKs()
	if err != nil {
		errs = append(errs, err)
	} else {
		c.PreviousKEKs = prev
	}
	if c.BaseURL != "" {
		if err := ValidateBaseURL(c.BaseURL); err != nil {
			errs = append(errs, fmt.Errorf("CF_BASE_URL %w", err))
		}
	}
	if _, err := parseLevel(c.LogLevel); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return Config{}, fmt.Errorf("config: %w", errors.Join(errs...))
	}
	return c, nil
}

// ValidateBaseURL checks that s is an absolute http or https URL with a host.
func ValidateBaseURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("must be an absolute http(s) URL")
	}
	return nil
}

// SlogLevel returns the configured log level, defaulting to info.
func (c Config) SlogLevel() slog.Level {
	l, err := parseLevel(c.LogLevel)
	if err != nil {
		return slog.LevelInfo
	}
	return l
}

func loadKEK() (KEKConfig, error) {
	envVal := strings.TrimSpace(os.Getenv("CF_KEK"))
	path := strings.TrimSpace(os.Getenv("CF_KEK_FILE"))
	vaultAddr := strings.TrimSpace(os.Getenv("CF_KEK_VAULT_ADDR"))

	present := 0
	for _, v := range []string{envVal, path, vaultAddr} {
		if v != "" {
			present++
		}
	}
	switch {
	case present > 1:
		return KEKConfig{}, errors.New("set only one of CF_KEK, CF_KEK_FILE and CF_KEK_VAULT_ADDR")
	case envVal != "":
		k, err := decodeKey(envVal)
		if err != nil {
			return KEKConfig{}, fmt.Errorf("CF_KEK: %w", err)
		}
		return KEKConfig{Kind: KEKKindStatic, Source: "env", Key: k}, nil
	case path != "":
		raw, err := os.ReadFile(path)
		if err != nil {
			return KEKConfig{}, fmt.Errorf("CF_KEK_FILE: %w", err)
		}
		if len(raw) == KEKSize {
			return KEKConfig{Kind: KEKKindStatic, Source: "file", Key: raw}, nil
		}
		k, err := decodeKey(strings.TrimSpace(string(raw)))
		if err != nil {
			return KEKConfig{}, fmt.Errorf("CF_KEK_FILE %s: %w", path, err)
		}
		return KEKConfig{Kind: KEKKindStatic, Source: "file", Key: k}, nil
	case vaultAddr != "":
		return loadVaultKEK(vaultAddr, "CF_KEK_VAULT")
	default:
		return KEKConfig{}, errors.New("one of CF_KEK, CF_KEK_FILE or CF_KEK_VAULT_ADDR is required")
	}
}

// loadPreviousKEKs reads CF_KEK_PREVIOUS[_FILE] and CF_KEK_PREVIOUS_VAULT_*:
// a KEK a rotation moved away from, still configured so the multi-wrapper
// envelope can decrypt not-yet-rewrapped data (Task 5). At most one static
// candidate (CF_KEK_PREVIOUS or CF_KEK_PREVIOUS_FILE, never both) and at
// most one vault-transit candidate may be set; either, both, or neither is
// valid. Whether a candidate happens to equal the active KEK is checked by
// the caller once both are built into crypto.KeyWrapper values
// (cmd/certforge/kek.go): this package never derives a KEK's id, the same
// way loadKEK above never does either.
func loadPreviousKEKs() ([]KEKConfig, error) {
	var out []KEKConfig
	envVal := strings.TrimSpace(os.Getenv("CF_KEK_PREVIOUS"))
	path := strings.TrimSpace(os.Getenv("CF_KEK_PREVIOUS_FILE"))
	switch {
	case envVal != "" && path != "":
		return nil, errors.New("set only one of CF_KEK_PREVIOUS and CF_KEK_PREVIOUS_FILE")
	case envVal != "":
		k, err := decodeKey(envVal)
		if err != nil {
			return nil, fmt.Errorf("CF_KEK_PREVIOUS: %w", err)
		}
		out = append(out, KEKConfig{Kind: KEKKindStatic, Source: "env", Key: k})
	case path != "":
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("CF_KEK_PREVIOUS_FILE: %w", err)
		}
		k := raw
		if len(k) != KEKSize {
			k, err = decodeKey(strings.TrimSpace(string(raw)))
			if err != nil {
				return nil, fmt.Errorf("CF_KEK_PREVIOUS_FILE %s: %w", path, err)
			}
		}
		out = append(out, KEKConfig{Kind: KEKKindStatic, Source: "file", Key: k})
	}

	if vaultAddr := strings.TrimSpace(os.Getenv("CF_KEK_PREVIOUS_VAULT_ADDR")); vaultAddr != "" {
		vk, err := loadVaultKEK(vaultAddr, "CF_KEK_PREVIOUS_VAULT")
		if err != nil {
			return nil, err
		}
		out = append(out, vk)
	}
	return out, nil
}

// loadVaultKEK reads the <prefix>_TRANSIT_KEY, _MOUNT, _NAMESPACE, _CA_FILE,
// _TOKEN[_FILE], _ROLE_ID and _SECRET_ID[_FILE] variables for a
// Transit-backed KEK at addr: prefix is CF_KEK_VAULT for the active KEK and
// CF_KEK_PREVIOUS_VAULT for a previous one (same suffixes). _FILE variants
// are trimmed after reading. Exactly one auth method (token or AppRole)
// must be configured; a mix, or neither, is an error naming the variables
// involved, never any value read from them.
func loadVaultKEK(addr, prefix string) (KEKConfig, error) {
	transitKey := strings.TrimSpace(os.Getenv(prefix + "_TRANSIT_KEY"))
	if transitKey == "" {
		return KEKConfig{}, fmt.Errorf("%s_TRANSIT_KEY is required with %s_ADDR", prefix, prefix)
	}
	vk := &VaultKEK{
		Addr:      addr,
		Key:       transitKey,
		Mount:     envOr(prefix+"_MOUNT", "transit"),
		Namespace: strings.TrimSpace(os.Getenv(prefix + "_NAMESPACE")),
	}
	if caFile := strings.TrimSpace(os.Getenv(prefix + "_CA_FILE")); caFile != "" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return KEKConfig{}, fmt.Errorf("%s_CA_FILE: %w", prefix, err)
		}
		vk.CAFile = string(raw)
	}

	token := strings.TrimSpace(os.Getenv(prefix + "_TOKEN"))
	tokenFile := strings.TrimSpace(os.Getenv(prefix + "_TOKEN_FILE"))
	roleID := strings.TrimSpace(os.Getenv(prefix + "_ROLE_ID"))
	secretID := strings.TrimSpace(os.Getenv(prefix + "_SECRET_ID"))
	secretIDFile := strings.TrimSpace(os.Getenv(prefix + "_SECRET_ID_FILE"))

	tokenAuth := token != "" || tokenFile != ""
	approleAuth := roleID != "" || secretID != "" || secretIDFile != ""

	switch {
	case tokenAuth && approleAuth:
		return KEKConfig{}, fmt.Errorf("set only one auth method for %s_ADDR: %s_TOKEN[_FILE] or %s_ROLE_ID and %s_SECRET_ID[_FILE]", prefix, prefix, prefix, prefix)
	case tokenAuth:
		if token != "" && tokenFile != "" {
			return KEKConfig{}, fmt.Errorf("set only one of %s_TOKEN and %s_TOKEN_FILE", prefix, prefix)
		}
		if tokenFile != "" {
			raw, err := os.ReadFile(tokenFile)
			if err != nil {
				return KEKConfig{}, fmt.Errorf("%s_TOKEN_FILE: %w", prefix, err)
			}
			token = strings.TrimSpace(string(raw))
		}
		vk.Token = token
	case approleAuth:
		if secretID != "" && secretIDFile != "" {
			return KEKConfig{}, fmt.Errorf("set only one of %s_SECRET_ID and %s_SECRET_ID_FILE", prefix, prefix)
		}
		if roleID == "" || (secretID == "" && secretIDFile == "") {
			return KEKConfig{}, fmt.Errorf("%s_ROLE_ID and %s_SECRET_ID[_FILE] are both required for AppRole auth", prefix, prefix)
		}
		if secretIDFile != "" {
			raw, err := os.ReadFile(secretIDFile)
			if err != nil {
				return KEKConfig{}, fmt.Errorf("%s_SECRET_ID_FILE: %w", prefix, err)
			}
			secretID = strings.TrimSpace(string(raw))
		}
		vk.RoleID, vk.SecretID = roleID, secretID
	default:
		return KEKConfig{}, fmt.Errorf("%s_ADDR requires %s_TOKEN[_FILE] or %s_ROLE_ID and %s_SECRET_ID[_FILE]", prefix, prefix, prefix, prefix)
	}
	return KEKConfig{Kind: KEKKindVaultTransit, Source: "vault", Vault: vk}, nil
}

func decodeKey(s string) ([]byte, error) {
	encs := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, enc := range encs {
		b, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		if len(b) != KEKSize {
			return nil, fmt.Errorf("key must decode to %d bytes, got %d", KEKSize, len(b))
		}
		return b, nil
	}
	return nil, errors.New("key is not valid base64")
}

func parseLevel(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("CF_LOG_LEVEL must be debug, info, warn, or error, got %q", s)
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
