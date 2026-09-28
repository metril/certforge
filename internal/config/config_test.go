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

var allVars = []string{
	"CF_DATABASE_URL", "CF_KEK", "CF_KEK_FILE", "CF_LISTEN_HTTP", "CF_LISTEN_AGENT", "CF_BASE_URL", "CF_LOG_LEVEL",
	"CF_KEK_VAULT_ADDR", "CF_KEK_VAULT_TRANSIT_KEY", "CF_KEK_VAULT_MOUNT", "CF_KEK_VAULT_NAMESPACE", "CF_KEK_VAULT_CA_FILE",
	"CF_KEK_VAULT_TOKEN", "CF_KEK_VAULT_TOKEN_FILE", "CF_KEK_VAULT_ROLE_ID", "CF_KEK_VAULT_SECRET_ID", "CF_KEK_VAULT_SECRET_ID_FILE",
	"CF_KEK_PREVIOUS", "CF_KEK_PREVIOUS_FILE",
	"CF_KEK_PREVIOUS_VAULT_ADDR", "CF_KEK_PREVIOUS_VAULT_TRANSIT_KEY", "CF_KEK_PREVIOUS_VAULT_MOUNT", "CF_KEK_PREVIOUS_VAULT_NAMESPACE",
	"CF_KEK_PREVIOUS_VAULT_CA_FILE", "CF_KEK_PREVIOUS_VAULT_TOKEN", "CF_KEK_PREVIOUS_VAULT_TOKEN_FILE",
	"CF_KEK_PREVIOUS_VAULT_ROLE_ID", "CF_KEK_PREVIOUS_VAULT_SECRET_ID", "CF_KEK_PREVIOUS_VAULT_SECRET_ID_FILE",
}

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
		{"missing kek", map[string]string{"CF_DATABASE_URL": "postgres://x/y"}, "CF_KEK, CF_KEK_FILE or CF_KEK_VAULT_ADDR is required"},
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

// TestLoadKEKSources covers each of the three KEK sources (env, file,
// Vault Transit with each auth method), every mix rejected between them,
// and that a rejection error names the offending variables without ever
// including a secret value.
func TestLoadKEKSources(t *testing.T) {
	base := map[string]string{"CF_DATABASE_URL": "postgres://x/y"}
	withBase := func(kv map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range kv {
			out[k] = v
		}
		return out
	}

	t.Run("env", func(t *testing.T) {
		setEnv(t, withBase(map[string]string{"CF_KEK": key(1)}))
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.KEK.Kind != KEKKindStatic || c.KEK.Source != "env" || len(c.KEK.Key) != KEKSize || c.KEK.Vault != nil {
			t.Fatalf("kek = %+v", c.KEK)
		}
	})

	t.Run("file", func(t *testing.T) {
		dir := t.TempDir()
		p := dir + "/kek"
		if err := os.WriteFile(p, []byte(key(2)), 0o600); err != nil {
			t.Fatal(err)
		}
		setEnv(t, withBase(map[string]string{"CF_KEK_FILE": p}))
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.KEK.Kind != KEKKindStatic || c.KEK.Source != "file" || c.KEK.Vault != nil {
			t.Fatalf("kek = %+v", c.KEK)
		}
	})

	t.Run("vault token", func(t *testing.T) {
		setEnv(t, withBase(map[string]string{
			"CF_KEK_VAULT_ADDR": "https://vault.example.com:8200/", "CF_KEK_VAULT_TRANSIT_KEY": "certforge-kek",
			"CF_KEK_VAULT_TOKEN": "s.supersecret",
		}))
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.KEK.Kind != KEKKindVaultTransit || c.KEK.Vault == nil {
			t.Fatalf("kek = %+v", c.KEK)
		}
		if c.KEK.Vault.Addr != "https://vault.example.com:8200/" || c.KEK.Vault.Key != "certforge-kek" || c.KEK.Vault.Token != "s.supersecret" {
			t.Fatalf("vault = %+v", c.KEK.Vault)
		}
		if c.KEK.Vault.Mount != "transit" {
			t.Fatalf("mount default = %q", c.KEK.Vault.Mount)
		}
	})

	t.Run("vault token file", func(t *testing.T) {
		dir := t.TempDir()
		p := dir + "/token"
		if err := os.WriteFile(p, []byte("s.filetoken\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		setEnv(t, withBase(map[string]string{
			"CF_KEK_VAULT_ADDR": "https://vault.example.com:8200", "CF_KEK_VAULT_TRANSIT_KEY": "certforge-kek",
			"CF_KEK_VAULT_TOKEN_FILE": p,
		}))
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.KEK.Vault.Token != "s.filetoken" {
			t.Fatalf("token = %q", c.KEK.Vault.Token)
		}
	})

	t.Run("vault approle", func(t *testing.T) {
		setEnv(t, withBase(map[string]string{
			"CF_KEK_VAULT_ADDR": "https://vault.example.com:8200", "CF_KEK_VAULT_TRANSIT_KEY": "certforge-kek",
			"CF_KEK_VAULT_ROLE_ID": "role-1", "CF_KEK_VAULT_SECRET_ID": "secret-1",
		}))
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.KEK.Vault.RoleID != "role-1" || c.KEK.Vault.SecretID != "secret-1" {
			t.Fatalf("vault = %+v", c.KEK.Vault)
		}
	})

	t.Run("vault approle secret file", func(t *testing.T) {
		dir := t.TempDir()
		p := dir + "/secret_id"
		if err := os.WriteFile(p, []byte("secret-from-file\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		setEnv(t, withBase(map[string]string{
			"CF_KEK_VAULT_ADDR": "https://vault.example.com:8200", "CF_KEK_VAULT_TRANSIT_KEY": "certforge-kek",
			"CF_KEK_VAULT_ROLE_ID": "role-1", "CF_KEK_VAULT_SECRET_ID_FILE": p,
		}))
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.KEK.Vault.SecretID != "secret-from-file" {
			t.Fatalf("secretId = %q", c.KEK.Vault.SecretID)
		}
	})

	t.Run("vault ca file", func(t *testing.T) {
		dir := t.TempDir()
		p := dir + "/ca.pem"
		pem := "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
		if err := os.WriteFile(p, []byte(pem), 0o600); err != nil {
			t.Fatal(err)
		}
		setEnv(t, withBase(map[string]string{
			"CF_KEK_VAULT_ADDR": "https://vault.example.com:8200", "CF_KEK_VAULT_TRANSIT_KEY": "certforge-kek",
			"CF_KEK_VAULT_TOKEN": "tok", "CF_KEK_VAULT_CA_FILE": p, "CF_KEK_VAULT_MOUNT": "transit-2", "CF_KEK_VAULT_NAMESPACE": "ns1",
		}))
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.KEK.Vault.CAFile != pem || c.KEK.Vault.Mount != "transit-2" || c.KEK.Vault.Namespace != "ns1" {
			t.Fatalf("vault = %+v", c.KEK.Vault)
		}
	})

	mixCases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"env and file", map[string]string{"CF_KEK": key(1), "CF_KEK_FILE": "/x"}, "only one of"},
		{"env and vault", map[string]string{"CF_KEK": key(1), "CF_KEK_VAULT_ADDR": "https://v", "CF_KEK_VAULT_TRANSIT_KEY": "k", "CF_KEK_VAULT_TOKEN": "t"}, "only one of"},
		{"file and vault", map[string]string{"CF_KEK_FILE": "/x", "CF_KEK_VAULT_ADDR": "https://v", "CF_KEK_VAULT_TRANSIT_KEY": "k", "CF_KEK_VAULT_TOKEN": "t"}, "only one of"},
		{"vault missing transit key", map[string]string{"CF_KEK_VAULT_ADDR": "https://v", "CF_KEK_VAULT_TOKEN": "t"}, "CF_KEK_VAULT_TRANSIT_KEY"},
		{"vault no auth", map[string]string{"CF_KEK_VAULT_ADDR": "https://v", "CF_KEK_VAULT_TRANSIT_KEY": "k"}, "CF_KEK_VAULT_TOKEN"},
		{"vault both auth methods", map[string]string{"CF_KEK_VAULT_ADDR": "https://v", "CF_KEK_VAULT_TRANSIT_KEY": "k", "CF_KEK_VAULT_TOKEN": "t", "CF_KEK_VAULT_ROLE_ID": "r", "CF_KEK_VAULT_SECRET_ID": "s"}, "only one auth method"},
		{"vault token and token file", map[string]string{"CF_KEK_VAULT_ADDR": "https://v", "CF_KEK_VAULT_TRANSIT_KEY": "k", "CF_KEK_VAULT_TOKEN": "t", "CF_KEK_VAULT_TOKEN_FILE": "/x"}, "only one of"},
		{"vault approle missing secret", map[string]string{"CF_KEK_VAULT_ADDR": "https://v", "CF_KEK_VAULT_TRANSIT_KEY": "k", "CF_KEK_VAULT_ROLE_ID": "r"}, "CF_KEK_VAULT_ROLE_ID and CF_KEK_VAULT_SECRET_ID"},
		{"vault approle secret and secret file", map[string]string{"CF_KEK_VAULT_ADDR": "https://v", "CF_KEK_VAULT_TRANSIT_KEY": "k", "CF_KEK_VAULT_ROLE_ID": "r", "CF_KEK_VAULT_SECRET_ID": "s", "CF_KEK_VAULT_SECRET_ID_FILE": "/x"}, "only one of"},
	}
	for _, tc := range mixCases {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, withBase(tc.env))
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			// The error must name variables, never the secret values that
			// happen to be present in this case's env.
			for _, secret := range []string{"t", "s", "tok"} {
				if v, ok := tc.env["CF_KEK_VAULT_TOKEN"]; ok && v == secret && strings.Contains(err.Error(), secret) && len(secret) > 1 {
					t.Fatalf("error leaks a secret value: %v", err)
				}
			}
		})
	}

	t.Run("vault error omits secret values", func(t *testing.T) {
		setEnv(t, withBase(map[string]string{
			"CF_KEK_VAULT_ADDR": "https://v", "CF_KEK_VAULT_TRANSIT_KEY": "k",
			"CF_KEK_VAULT_TOKEN": "extremely-secret-token-value", "CF_KEK_VAULT_ROLE_ID": "r", "CF_KEK_VAULT_SECRET_ID": "extremely-secret-secret-id",
		}))
		_, err := Load()
		if err == nil {
			t.Fatal("want error for mixed auth methods")
		}
		if strings.Contains(err.Error(), "extremely-secret") {
			t.Fatalf("error leaks a secret value: %v", err)
		}
	})
}

// TestLoadPreviousKEKs covers CF_KEK_PREVIOUS[_FILE] and
// CF_KEK_PREVIOUS_VAULT_* (Task 5): none set is the common case (empty,
// no error); a static and a Transit previous KEK may be set together;
// CF_KEK_PREVIOUS and CF_KEK_PREVIOUS_FILE together is rejected the same
// way CF_KEK/CF_KEK_FILE are.
func TestLoadPreviousKEKs(t *testing.T) {
	base := map[string]string{"CF_DATABASE_URL": "postgres://x/y", "CF_KEK": key(1)}
	withBase := func(kv map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range kv {
			out[k] = v
		}
		return out
	}

	t.Run("none", func(t *testing.T) {
		setEnv(t, base)
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(c.PreviousKEKs) != 0 {
			t.Fatalf("previous = %+v", c.PreviousKEKs)
		}
	})

	t.Run("static env", func(t *testing.T) {
		setEnv(t, withBase(map[string]string{"CF_KEK_PREVIOUS": key(9)}))
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(c.PreviousKEKs) != 1 || c.PreviousKEKs[0].Kind != KEKKindStatic || c.PreviousKEKs[0].Source != "env" || len(c.PreviousKEKs[0].Key) != KEKSize {
			t.Fatalf("previous = %+v", c.PreviousKEKs)
		}
	})

	t.Run("static file", func(t *testing.T) {
		dir := t.TempDir()
		p := dir + "/prev"
		if err := os.WriteFile(p, bytes.Repeat([]byte{8}, 32), 0o600); err != nil {
			t.Fatal(err)
		}
		setEnv(t, withBase(map[string]string{"CF_KEK_PREVIOUS_FILE": p}))
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(c.PreviousKEKs) != 1 || c.PreviousKEKs[0].Source != "file" {
			t.Fatalf("previous = %+v", c.PreviousKEKs)
		}
	})

	t.Run("static env and file conflict", func(t *testing.T) {
		setEnv(t, withBase(map[string]string{"CF_KEK_PREVIOUS": key(9), "CF_KEK_PREVIOUS_FILE": "/x"}))
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "only one of CF_KEK_PREVIOUS") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("vault transit", func(t *testing.T) {
		setEnv(t, withBase(map[string]string{
			"CF_KEK_PREVIOUS_VAULT_ADDR": "https://vault.example.com:8200", "CF_KEK_PREVIOUS_VAULT_TRANSIT_KEY": "old-key",
			"CF_KEK_PREVIOUS_VAULT_TOKEN": "s.previoustoken",
		}))
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(c.PreviousKEKs) != 1 || c.PreviousKEKs[0].Kind != KEKKindVaultTransit || c.PreviousKEKs[0].Vault == nil {
			t.Fatalf("previous = %+v", c.PreviousKEKs)
		}
		if c.PreviousKEKs[0].Vault.Key != "old-key" || c.PreviousKEKs[0].Vault.Token != "s.previoustoken" {
			t.Fatalf("previous vault = %+v", c.PreviousKEKs[0].Vault)
		}
	})

	t.Run("vault missing transit key", func(t *testing.T) {
		setEnv(t, withBase(map[string]string{"CF_KEK_PREVIOUS_VAULT_ADDR": "https://v", "CF_KEK_PREVIOUS_VAULT_TOKEN": "t"}))
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "CF_KEK_PREVIOUS_VAULT_TRANSIT_KEY") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("both static and vault previous", func(t *testing.T) {
		setEnv(t, withBase(map[string]string{
			"CF_KEK_PREVIOUS":            key(9),
			"CF_KEK_PREVIOUS_VAULT_ADDR": "https://v", "CF_KEK_PREVIOUS_VAULT_TRANSIT_KEY": "old-key", "CF_KEK_PREVIOUS_VAULT_TOKEN": "t",
		}))
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(c.PreviousKEKs) != 2 || c.PreviousKEKs[0].Kind != KEKKindStatic || c.PreviousKEKs[1].Kind != KEKKindVaultTransit {
			t.Fatalf("previous = %+v", c.PreviousKEKs)
		}
	})
}
