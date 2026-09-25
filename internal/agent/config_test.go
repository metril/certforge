package agent

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadConfig(t *testing.T) {
	c, err := LoadConfig(env(nil), "1.0.0")
	if err != nil || c.DataDir != "/data" || c.PullInterval != 0 || len(c.HookAllow) != 0 || len(c.WriteAllow) != 0 || c.Version != "1.0.0" {
		t.Fatalf("defaults %+v %v", c, err)
	}
	c, err = LoadConfig(env(map[string]string{"CF_AGENT_DATA": "/var/lib/cf", "CF_HOOK_ALLOW": "/usr/sbin/nginx: /usr/local/bin/reload",
		"CF_WRITE_ALLOW": "/etc/traefik/dynamic: /etc/ssl", "CF_AGENT_PULL_INTERVAL": "15m", "CF_AGENT_TOKEN": " tok "}), "dev")
	if err != nil || c.DataDir != "/var/lib/cf" || !slices.Equal(c.HookAllow, []string{"/usr/sbin/nginx", "/usr/local/bin/reload"}) ||
		!slices.Equal(c.WriteAllow, []string{"/etc/traefik/dynamic", "/etc/ssl"}) ||
		c.PullInterval != 15*time.Minute || c.Token != "tok" {
		t.Fatalf("set %+v %v", c, err)
	}
	for name, m := range map[string]map[string]string{
		"relative hook":  {"CF_HOOK_ALLOW": "nginx"},
		"unclean hook":   {"CF_HOOK_ALLOW": "/usr/../bin/sh"},
		"relative write": {"CF_WRITE_ALLOW": "etc/ssl"},
		"unclean write":  {"CF_WRITE_ALLOW": "/etc/../ssl"},
		"short pull":     {"CF_AGENT_PULL_INTERVAL": "30s"},
		"bad pull":       {"CF_AGENT_PULL_INTERVAL": "soon"},
	} {
		if _, err := LoadConfig(env(m), "dev"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestResolveToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "token")
	c := Config{TokenFile: f}
	if tok, err := c.ResolveToken(); err != nil || tok != "" {
		t.Fatalf("missing file: %q %v", tok, err)
	}
	if err := os.WriteFile(f, []byte("cf1.x.y.z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, _ := c.ResolveToken(); tok != "cf1.x.y.z" {
		t.Fatalf("file token %q", tok)
	}
	if tok, _ := (Config{Token: "direct", TokenFile: f}).ResolveToken(); tok != "direct" {
		t.Fatalf("env wins: %q", tok)
	}
}
