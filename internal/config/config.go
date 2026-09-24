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

// KEKConfig is the key-encryption key and where it came from ("env" or "file").
type KEKConfig struct {
	Source string
	Key    []byte
}

// Config is the bootstrap configuration read from CF_* environment variables.
type Config struct {
	DatabaseURL string
	KEK         KEKConfig
	ListenHTTP  string
	ListenAgent string
	BaseURL     string
	LogLevel    string
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
	switch {
	case envVal != "" && path != "":
		return KEKConfig{}, errors.New("set only one of CF_KEK and CF_KEK_FILE")
	case envVal != "":
		k, err := decodeKey(envVal)
		if err != nil {
			return KEKConfig{}, fmt.Errorf("CF_KEK: %w", err)
		}
		return KEKConfig{Source: "env", Key: k}, nil
	case path != "":
		raw, err := os.ReadFile(path)
		if err != nil {
			return KEKConfig{}, fmt.Errorf("CF_KEK_FILE: %w", err)
		}
		if len(raw) == KEKSize {
			return KEKConfig{Source: "file", Key: raw}, nil
		}
		k, err := decodeKey(strings.TrimSpace(string(raw)))
		if err != nil {
			return KEKConfig{}, fmt.Errorf("CF_KEK_FILE %s: %w", path, err)
		}
		return KEKConfig{Source: "file", Key: k}, nil
	default:
		return KEKConfig{}, errors.New("one of CF_KEK or CF_KEK_FILE is required (32 random bytes, base64)")
	}
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
