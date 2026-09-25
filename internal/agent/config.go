// Package agent is certforge-agent: enrolment, the mTLS client, the
// reconcile loop that installs grants, the Traefik target, and hooks.
package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config is read from CF_AGENT_* and CF_HOOK_ALLOW.
type Config struct {
	DataDir      string        // CF_AGENT_DATA, default /data
	Token        string        // CF_AGENT_TOKEN
	TokenFile    string        // CF_AGENT_TOKEN_FILE
	HookAllow    []string      // CF_HOOK_ALLOW, colon-separated absolute paths; empty disables hooks
	PullInterval time.Duration // CF_AGENT_PULL_INTERVAL, 0 = socket only
	Version      string
}

// LoadConfig reads the environment through getenv.
func LoadConfig(getenv func(string) string, version string) (Config, error) {
	c := Config{DataDir: "/data", Version: version}
	if v := strings.TrimSpace(getenv("CF_AGENT_DATA")); v != "" {
		c.DataDir = v
	}
	c.Token = strings.TrimSpace(getenv("CF_AGENT_TOKEN"))
	c.TokenFile = strings.TrimSpace(getenv("CF_AGENT_TOKEN_FILE"))
	for _, p := range strings.Split(getenv("CF_HOOK_ALLOW"), ":") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, fmt.Errorf("CF_HOOK_ALLOW: %q is not a clean absolute path", p)
		}
		c.HookAllow = append(c.HookAllow, p)
	}
	if v := strings.TrimSpace(getenv("CF_AGENT_PULL_INTERVAL")); v != "" && v != "0" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			return c, fmt.Errorf("CF_AGENT_PULL_INTERVAL: %q must be a duration of at least 1m, or 0", v)
		}
		c.PullInterval = d
	}
	return c, nil
}

// ResolveToken returns CF_AGENT_TOKEN, else the token file's contents, else
// "" (a missing token file is not an error: run waits for it).
func (c Config) ResolveToken() (string, error) {
	if c.Token != "" || c.TokenFile == "" {
		return c.Token, nil
	}
	b, err := os.ReadFile(c.TokenFile)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("CF_AGENT_TOKEN_FILE: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
