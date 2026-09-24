package config

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var allVars = []string{"CF_DATABASE_URL", "CF_KEK", "CF_KEK_FILE", "CF_LISTEN_HTTP", "CF_LISTEN_AGENT", "CF_BASE_URL", "CF_LOG_LEVEL"}

func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range allVars {
		t.Setenv(k, "")
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func key(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func TestLoadDefaults(t *testing.T) {
	setEnv(t, map[string]string{"CF_DATABASE_URL": "postgres://x/y", "CF_KEK": key(1)})
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenHTTP != ":8080" || c.ListenAgent != ":8443" || c.LogLevel != "info" {
		t.Fatalf("defaults: %+v", c)
	}
	if c.KEK.Source != "env" || len(c.KEK.Key) != KEKSize {
		t.Fatalf("kek: %s %d", c.KEK.Source, len(c.KEK.Key))
	}
	if c.SlogLevel() != slog.LevelInfo {
		t.Fatalf("level %v", c.SlogLevel())
	}
}

func TestLoadKEKFile(t *testing.T) {
	dir := t.TempDir()
	b64 := filepath.Join(dir, "b64")
	raw := filepath.Join(dir, "raw")
	if err := os.WriteFile(b64, []byte(key(2)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(raw, bytes.Repeat([]byte{3}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{b64, raw} {
		setEnv(t, map[string]string{"CF_DATABASE_URL": "postgres://x/y", "CF_KEK_FILE": p})
		c, err := Load()
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if c.KEK.Source != "file" || len(c.KEK.Key) != 32 {
			t.Fatalf("%s: %+v", p, c.KEK.Source)
		}
	}
}

func TestLoadBaseURLTrimmed(t *testing.T) {
	setEnv(t, map[string]string{"CF_DATABASE_URL": "postgres://x/y", "CF_KEK": key(1), "CF_BASE_URL": "https://certs.example.com/"})
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != "https://certs.example.com" {
		t.Fatalf("base url %q", c.BaseURL)
	}
}

func TestLoadErrors(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"missing db", map[string]string{"CF_KEK": key(1)}, "CF_DATABASE_URL is required"},
		{"missing kek", map[string]string{"CF_DATABASE_URL": "postgres://x/y"}, "CF_KEK or CF_KEK_FILE is required"},
		{"both kek", map[string]string{"CF_DATABASE_URL": "postgres://x/y", "CF_KEK": key(1), "CF_KEK_FILE": "/x"}, "only one of"},
		{"short kek", map[string]string{"CF_DATABASE_URL": "postgres://x/y", "CF_KEK": short}, "32 bytes"},
		{"bad base64", map[string]string{"CF_DATABASE_URL": "postgres://x/y", "CF_KEK": "!!!"}, "not valid base64"},
		{"missing file", map[string]string{"CF_DATABASE_URL": "postgres://x/y", "CF_KEK_FILE": "/nonexistent/kek"}, "CF_KEK_FILE"},
		{"bad base url", map[string]string{"CF_DATABASE_URL": "postgres://x/y", "CF_KEK": key(1), "CF_BASE_URL": "ftp://x"}, "CF_BASE_URL must be an absolute http(s) URL"},
		{"bad level", map[string]string{"CF_DATABASE_URL": "postgres://x/y", "CF_KEK": key(1), "CF_LOG_LEVEL": "loud"}, "CF_LOG_LEVEL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, tc.env)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), short) {
				t.Fatal("error leaks key material")
			}
		})
	}
}
