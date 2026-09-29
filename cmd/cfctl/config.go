package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Config is cfctl's resolved connection configuration.
type Config struct {
	URL   string
	Token string
}

// fileConfig is the shape of $XDG_CONFIG_HOME/cfctl/config.json.
type fileConfig struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// resolveConfig applies cfctl's config precedence: flags, then
// CFCTL_URL/CFCTL_TOKEN, then the config file. The file is only read when
// a flag or env var left the URL or token unset, so a fully-specified
// invocation never needs the file to exist (or, if it does exist, to have
// a safe mode). getenv abstracts os.Getenv so precedence is testable
// without touching the real process environment.
func resolveConfig(flagURL, flagToken string, getenv func(string) string) (Config, error) {
	cfg := Config{URL: flagURL, Token: flagToken}
	if cfg.URL == "" {
		cfg.URL = getenv("CFCTL_URL")
	}
	if cfg.Token == "" {
		cfg.Token = getenv("CFCTL_TOKEN")
	}
	if cfg.URL != "" && cfg.Token != "" {
		return cfg, nil
	}

	fc, err := readConfigFile(configFilePath(getenv))
	if err != nil {
		return Config{}, err
	}
	if cfg.URL == "" {
		cfg.URL = fc.URL
	}
	if cfg.Token == "" {
		cfg.Token = fc.Token
	}
	return cfg, nil
}

// configFilePath is $XDG_CONFIG_HOME/cfctl/config.json, falling back to
// $HOME/.config/cfctl/config.json when XDG_CONFIG_HOME is unset.
func configFilePath(getenv func(string) string) string {
	base := getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(getenv("HOME"), ".config")
	}
	return filepath.Join(base, "cfctl", "config.json")
}

// readConfigFile reads path, refusing a file whose mode grants any
// group or other permission bit ("config.json must be mode 0600"). A
// missing file is not an error: it returns a zero fileConfig, since flags
// and env may already supply everything a command needs.
func readConfigFile(path string) (fileConfig, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileConfig{}, nil
	}
	if err != nil {
		return fileConfig{}, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fileConfig{}, fmt.Errorf("%s must be mode 0600", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fileConfig{}, err
	}
	var fc fileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return fileConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	return fc, nil
}
