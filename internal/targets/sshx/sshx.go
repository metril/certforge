// Package sshx is a small SSH client for deploy targets: it dials through
// the httpx SSRF policy, pins the server host key (no trust-on-first-use),
// runs commands, and atomically writes files.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/metril/certforge/internal/notify/httpx"
)

// Opts configures Dial.
type Opts struct {
	// Host and Port are the SSH server address; Port zero means 22.
	Host string
	Port int
	// User is the login name.
	User string
	// Password and PrivateKeyPEM are the auth methods; at least one is
	// required. The key must not be passphrase-protected.
	Password      string
	PrivateKeyPEM string
	// HostKey is the pinned server key: a known_hosts-style line or a bare
	// "<type> <base64>" public key. It is required.
	HostKey string
	// AllowLoopback re-admits loopback and link-local hosts.
	AllowLoopback bool
	// Timeout bounds the dial and handshake. Zero uses httpx.Timeout.
	Timeout time.Duration
}

// Client is an established SSH connection.
type Client struct {
	c *ssh.Client
}

// parseHostKey accepts a known_hosts line or a bare "<type> <base64>" key.
func parseHostKey(s string) (ssh.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("sshx: host key is required")
	}
	if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s)); err == nil {
		return k, nil
	}
	if _, _, k, _, _, err := ssh.ParseKnownHosts([]byte(s)); err == nil {
		return k, nil
	}
	return nil, errors.New("sshx: host key is not a valid public key")
}

// Dial connects to o.Host, verifying the server against o.HostKey.
func Dial(ctx context.Context, o Opts) (*Client, error) {
	hk, err := parseHostKey(o.HostKey)
	if err != nil {
		return nil, err
	}
	var auth []ssh.AuthMethod
	if o.PrivateKeyPEM != "" {
		signer, err := ssh.ParsePrivateKey([]byte(o.PrivateKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("sshx: parse private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if o.Password != "" {
		auth = append(auth, ssh.Password(o.Password))
	}
	if len(auth) == 0 {
		return nil, errors.New("sshx: a password or private key is required")
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = httpx.Timeout
	}
	hc, err := httpx.New(httpx.Options{AllowLoopback: o.AllowLoopback, Timeout: timeout})
	if err != nil {
		return nil, err
	}
	port := o.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(o.Host, strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := hc.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sshx: dial: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:            o.User,
		Auth:            auth,
		HostKeyCallback: ssh.FixedHostKey(hk),
		Timeout:         timeout,
	}
	// The handshake takes no context; closing conn aborts it.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sshx: handshake: %w", err)
	}
	return &Client{c: ssh.NewClient(sc, chans, reqs)}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.c.Close() }

// Run executes cmd and returns its output and exit code. A non-zero exit is
// not an error; err is set only for transport failures or ctx expiry.
func (c *Client) Run(ctx context.Context, cmd string) (stdout, stderr []byte, exitCode int, err error) {
	return c.run(ctx, cmd, nil)
}

func (c *Client) run(ctx context.Context, cmd string, stdin []byte) ([]byte, []byte, int, error) {
	s, err := c.c.NewSession()
	if err != nil {
		return nil, nil, -1, fmt.Errorf("sshx: session: %w", err)
	}
	defer func() { _ = s.Close() }()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	if stdin != nil {
		s.Stdin = bytes.NewReader(stdin)
	}
	if err := s.Start(cmd); err != nil {
		return nil, nil, -1, fmt.Errorf("sshx: start: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	select {
	case <-ctx.Done():
		_ = s.Close()
		return nil, nil, -1, ctx.Err()
	case err := <-done:
		code := 0
		var ee *ssh.ExitError
		switch {
		case err == nil:
		case errors.As(err, &ee):
			code = ee.ExitStatus()
		default:
			return out.Bytes(), errb.Bytes(), -1, fmt.Errorf("sshx: wait: %w", err)
		}
		return out.Bytes(), errb.Bytes(), code, nil
	}
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// WriteFile writes data to path atomically: it streams to
// "<path>.tmp-certforge", chmods it to mode, then renames over path.
func (c *Client) WriteFile(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	tmp := shQuote(path + ".tmp-certforge")
	cmd := fmt.Sprintf("set -e; cat > %s && chmod %04o %s && mv -f %s %s",
		tmp, mode.Perm(), tmp, tmp, shQuote(path))
	if data == nil {
		data = []byte{}
	}
	_, stderr, code, err := c.run(ctx, cmd, data)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("sshx: write %s: exit %d: %s", path, code, strings.TrimSpace(string(stderr)))
	}
	return nil
}
