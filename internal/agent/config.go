// Package agent is certforge-agent: enrolment, the mTLS client, the
// reconcile loop that installs grants, the Traefik target, and hooks.
package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is read from CF_AGENT_*, CF_HOOK_ALLOW and CF_WRITE_ALLOW.
type Config struct {
	DataDir       string        // CF_AGENT_DATA, default /data
	Token         string        // CF_AGENT_TOKEN
	TokenFile     string        // CF_AGENT_TOKEN_FILE
	HookAllow     []string      // CF_HOOK_ALLOW, colon-separated absolute paths; empty disables hooks
	WriteAllow    []string      // CF_WRITE_ALLOW, colon-separated absolute directory prefixes; empty disables every write
	PullInterval  time.Duration // CF_AGENT_PULL_INTERVAL, 0 = socket only
	HTTP01Listen  string        // CF_AGENT_HTTP01_LISTEN, host:port; empty disables serving http-01
	TLSALPNListen string        // CF_AGENT_TLSALPN_LISTEN, host:port; empty disables serving tls-alpn-01
	Transport     string        // CF_AGENT_TRANSPORT: auto (default), mtls or proxy; only chooses which TLS roots are trusted
	Version       string
}

// Transport modes. Whatever the mode, the application layer signs and seals
// everything and checks the server's responder certificate against the agent
// CA bundle, so the choice never decides security, only which TLS server
// certificate is acceptable.
const (
	TransportAuto  = "auto"  // the agent-CA pin when the server presents an agent-CA chain, else the system roots
	TransportMTLS  = "mtls"  // the agent-CA pin only (the dedicated agent port)
	TransportProxy = "proxy" // the system roots only (a public, TLS-terminating proxy)
)

// ParseTransport validates a CF_AGENT_TRANSPORT value; "" is auto.
func ParseTransport(s string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "", TransportAuto:
		return TransportAuto, nil
	case TransportMTLS, TransportProxy:
		return v, nil
	default:
		return "", fmt.Errorf("CF_AGENT_TRANSPORT: %q must be auto, mtls or proxy", s)
	}
}

// parseColonPaths splits s on ':', trims blanks, drops empty entries and
// requires every remaining entry to be a clean absolute path.
func parseColonPaths(name, s string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(s, ":") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, fmt.Errorf("%s: %q is not a clean absolute path", name, p)
		}
		out = append(out, p)
	}
	return out, nil
}

// validateListen accepts "" (disabled) or a host:port with a numeric port
// from 1 to 65535 (the host may be empty, as in ":8080").
func validateListen(name, addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", nil
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("%s: %q must be host:port: %w", name, addr, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", fmt.Errorf("%s: %q must have a port from 1 to 65535", name, addr)
	}
	return addr, nil
}

// LoadConfig reads the environment through getenv.
func LoadConfig(getenv func(string) string, version string) (Config, error) {
	c := Config{DataDir: "/data", Transport: TransportAuto, Version: version}
	if v := strings.TrimSpace(getenv("CF_AGENT_DATA")); v != "" {
		c.DataDir = v
	}
	c.Token = strings.TrimSpace(getenv("CF_AGENT_TOKEN"))
	c.TokenFile = strings.TrimSpace(getenv("CF_AGENT_TOKEN_FILE"))
	hookAllow, err := parseColonPaths("CF_HOOK_ALLOW", getenv("CF_HOOK_ALLOW"))
	if err != nil {
		return c, err
	}
	c.HookAllow = hookAllow
	writeAllow, err := parseColonPaths("CF_WRITE_ALLOW", getenv("CF_WRITE_ALLOW"))
	if err != nil {
		return c, err
	}
	for _, p := range writeAllow {
		if p == "/" {
			return c, fmt.Errorf("CF_WRITE_ALLOW: %q must not be the filesystem root", p)
		}
	}
	c.WriteAllow = writeAllow
	if v := strings.TrimSpace(getenv("CF_AGENT_PULL_INTERVAL")); v != "" && v != "0" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			return c, fmt.Errorf("CF_AGENT_PULL_INTERVAL: %q must be a duration of at least 1m, or 0", v)
		}
		c.PullInterval = d
	}
	http01, err := validateListen("CF_AGENT_HTTP01_LISTEN", getenv("CF_AGENT_HTTP01_LISTEN"))
	if err != nil {
		return c, err
	}
	c.HTTP01Listen = http01
	tlsAlpn, err := validateListen("CF_AGENT_TLSALPN_LISTEN", getenv("CF_AGENT_TLSALPN_LISTEN"))
	if err != nil {
		return c, err
	}
	c.TLSALPNListen = tlsAlpn
	if c.Transport, err = ParseTransport(getenv("CF_AGENT_TRANSPORT")); err != nil {
		return c, err
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
