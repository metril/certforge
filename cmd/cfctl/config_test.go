package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// envMap returns a getenv func backed by m, so precedence tests never
// touch the real process environment.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeConfigFile(t *testing.T, dir string, mode os.FileMode, fc fileConfig) string {
	t.Helper()
	sub := filepath.Join(dir, "cfctl")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "config.json")
	data, err := json.Marshal(fc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestConfigPrecedence covers flags > env > file, and that a value
// present at a higher-precedence source never even looks at a lower one.
func TestConfigPrecedence(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, 0o600, fileConfig{URL: "https://file.example", Token: "file-token"})

	t.Run("flags win", func(t *testing.T) {
		cfg, err := resolveConfig("https://flag.example", "flag-token", envMap(map[string]string{
			"CFCTL_URL": "https://env.example", "CFCTL_TOKEN": "env-token", "XDG_CONFIG_HOME": dir,
		}))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.URL != "https://flag.example" || cfg.Token != "flag-token" {
			t.Fatalf("cfg = %+v", cfg)
		}
	})

	t.Run("env wins over file", func(t *testing.T) {
		cfg, err := resolveConfig("", "", envMap(map[string]string{
			"CFCTL_URL": "https://env.example", "CFCTL_TOKEN": "env-token", "XDG_CONFIG_HOME": dir,
		}))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.URL != "https://env.example" || cfg.Token != "env-token" {
			t.Fatalf("cfg = %+v", cfg)
		}
	})

	t.Run("file is the fallback", func(t *testing.T) {
		cfg, err := resolveConfig("", "", envMap(map[string]string{"XDG_CONFIG_HOME": dir}))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.URL != "https://file.example" || cfg.Token != "file-token" {
			t.Fatalf("cfg = %+v", cfg)
		}
	})

	t.Run("mixed sources per field", func(t *testing.T) {
		cfg, err := resolveConfig("https://flag.example", "", envMap(map[string]string{
			"CFCTL_TOKEN": "env-token", "XDG_CONFIG_HOME": dir,
		}))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.URL != "https://flag.example" || cfg.Token != "env-token" {
			t.Fatalf("cfg = %+v", cfg)
		}
	})

	t.Run("fully specified never touches a missing file", func(t *testing.T) {
		cfg, err := resolveConfig("https://flag.example", "flag-token", envMap(map[string]string{
			"XDG_CONFIG_HOME": filepath.Join(dir, "does-not-exist"),
		}))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.URL != "https://flag.example" || cfg.Token != "flag-token" {
			t.Fatalf("cfg = %+v", cfg)
		}
	})
}

// TestConfigRefusesWorldReadable covers the mode-0600 requirement: a
// config file readable by group or other is refused, not silently used.
func TestConfigRefusesWorldReadable(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, 0o644, fileConfig{URL: "https://file.example", Token: "file-token"})

	_, err := resolveConfig("", "", envMap(map[string]string{"XDG_CONFIG_HOME": dir}))
	if err == nil {
		t.Fatal("expected an error for a world-readable config file")
	}
	if !strings.Contains(err.Error(), "must be mode 0600") {
		t.Fatalf("err = %q, want it to mention mode 0600", err.Error())
	}
}

// TestConfigHomeFallback covers XDG_CONFIG_HOME unset, falling back to
// $HOME/.config.
func TestConfigHomeFallback(t *testing.T) {
	home := t.TempDir()
	writeConfigFile(t, filepath.Join(home, ".config"), 0o600, fileConfig{URL: "https://home.example", Token: "home-token"})

	cfg, err := resolveConfig("", "", envMap(map[string]string{"HOME": home}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "https://home.example" || cfg.Token != "home-token" {
		t.Fatalf("cfg = %+v", cfg)
	}
}
