// Package sshx is a small SSH client for deploy targets: it dials through
// the httpx SSRF policy, pins the server host key (no trust-on-first-use),
// runs commands, and atomically writes files.
package sshx

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
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
	// required. PrivateKeyPassphrase decrypts a passphrase-protected key.
	Password             string
	PrivateKeyPEM        string
	PrivateKeyPassphrase string
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

// Private key errors from ParseSigner.
var (
	ErrInvalidKey         = errors.New("not a valid PEM private key")
	ErrPassphraseRequired = errors.New("private key is passphrase-protected; set the passphrase")
	ErrWrongPassphrase    = errors.New("wrong passphrase for the private key")
)

// ParseSigner parses a PEM private key (OpenSSH, PKCS#1 or PKCS#8),
// decrypting it with passphrase when it is protected. CRLF line endings and
// surrounding whitespace are tolerated. Errors wrap ErrInvalidKey,
// ErrPassphraseRequired or ErrWrongPassphrase.
func ParseSigner(pem, passphrase string) (ssh.Signer, error) {
	b := []byte(strings.TrimSpace(strings.ReplaceAll(pem, "\r\n", "\n")) + "\n")
	signer, err := ssh.ParsePrivateKey(b)
	if err == nil {
		return signer, nil
	}
	var pm *ssh.PassphraseMissingError
	if !errors.As(err, &pm) {
		return nil, ErrInvalidKey
	}
	if passphrase == "" {
		return nil, ErrPassphraseRequired
	}
	signer, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(passphrase))
	switch {
	case err == nil:
		return signer, nil
	case errors.Is(err, x509.IncorrectPasswordError):
		return nil, ErrWrongPassphrase
	default:
		return nil, ErrInvalidKey
	}
}

// ParseHostKey accepts a known_hosts line or a bare "<type> <base64>" key.
func ParseHostKey(s string) (ssh.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("sshx: host key is required")
	}
	if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s)); err == nil {
		return k, nil
	}
	if marker, _, k, _, _, err := ssh.ParseKnownHosts([]byte(s)); err == nil {
		if marker != "" {
			return nil, fmt.Errorf("sshx: host key marker %q is not supported", marker)
		}
		return k, nil
	}
	return nil, errors.New("sshx: host key is not a valid public key")
}

// hostKeyAlgorithms restricts negotiation to the pinned key's type, so a
// multi-key server cannot present a different (unpinned) type.
func hostKeyAlgorithms(k ssh.PublicKey) []string {
	if k.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{k.Type()}
}

// Dial connects to o.Host, verifying the server against o.HostKey.
func Dial(ctx context.Context, o Opts) (*Client, error) {
	hk, err := ParseHostKey(o.HostKey)
	if err != nil {
		return nil, err
	}
	var auth []ssh.AuthMethod
	if o.PrivateKeyPEM != "" {
		signer, err := ParseSigner(o.PrivateKeyPEM, o.PrivateKeyPassphrase)
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
		User:              o.User,
		Auth:              auth,
		HostKeyCallback:   ssh.FixedHostKey(hk),
		HostKeyAlgorithms: hostKeyAlgorithms(hk),
		Timeout:           timeout,
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
	if path == "" || !strings.HasPrefix(path, "/") {
		return fmt.Errorf("sshx: remote path %q must be absolute", path)
	}
	tmp := shQuote(path + ".tmp-certforge")
	cmd := fmt.Sprintf("umask 077; rm -f -- %s; set -e; cat > %s && chmod %04o -- %s && mv -f -- %s %s",
		tmp, tmp, mode.Perm(), tmp, tmp, shQuote(path))
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

var scpNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// scpAck reads one SCP reply: 0 is success, 1 and 2 carry a message line.
func scpAck(r *bufio.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("sshx: scp: %w", err)
	}
	if b == 0 {
		return nil
	}
	msg, _ := r.ReadString('\n')
	return fmt.Errorf("sshx: scp: remote error: %s", strings.TrimSpace(msg))
}

// WriteFileSCP uploads data as name in the remote's default directory with
// the SCP sink protocol ("scp -t"), for devices without a POSIX shell such
// as RouterOS. name must match ^[A-Za-z0-9._-]{1,64}$ and is passed to the
// remote command unquoted, since such devices may keep quotes in the name.
func (c *Client) WriteFileSCP(ctx context.Context, name string, data []byte, mode os.FileMode) error {
	if !scpNameRe.MatchString(name) {
		return fmt.Errorf("sshx: scp name %q must match %s", name, scpNameRe)
	}
	s, err := c.c.NewSession()
	if err != nil {
		return fmt.Errorf("sshx: session: %w", err)
	}
	defer func() { _ = s.Close() }()
	in, err := s.StdinPipe()
	if err != nil {
		return fmt.Errorf("sshx: scp: %w", err)
	}
	out, err := s.StdoutPipe()
	if err != nil {
		return fmt.Errorf("sshx: scp: %w", err)
	}
	if err := s.Start("scp -t " + name); err != nil {
		return fmt.Errorf("sshx: start: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	r := bufio.NewReader(out)
	werr := func(err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if err := scpAck(r); err != nil {
		return werr(err)
	}
	if _, err := fmt.Fprintf(in, "C%04o %d %s\n", mode.Perm(), len(data), name); err != nil {
		return werr(fmt.Errorf("sshx: scp: %w", err))
	}
	if err := scpAck(r); err != nil {
		return werr(err)
	}
	if _, err := in.Write(append(append([]byte{}, data...), 0)); err != nil {
		return werr(fmt.Errorf("sshx: scp: %w", err))
	}
	if err := scpAck(r); err != nil {
		return werr(err)
	}
	_ = in.Close()
	if err := s.Wait(); err != nil {
		var ee *ssh.ExitError
		if !errors.As(err, &ee) || ee.ExitStatus() != 0 {
			return werr(fmt.Errorf("sshx: scp: %w", err))
		}
	}
	return nil
}

// HostKey is one host key a server offers.
type HostKey struct {
	// Type is the key type, e.g. "ssh-ed25519".
	Type string
	// Line is the "<type> <base64>" public key to pin.
	Line string
	// Sha256 is the "SHA256:..." fingerprint.
	Sha256 string
}

var scanAlgos = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512}

var errScanDone = errors.New("sshx: host key recorded")

// ScanHostKeys connects once per host key algorithm and records the key the
// server offers, like ssh-keyscan. Algorithms the server rejects are skipped;
// it errors when the dial fails or no key is found.
func ScanHostKeys(ctx context.Context, host string, port int, allowLoopback bool) ([]HostKey, error) {
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(ctx, httpx.PeekTimeout)
	defer cancel()
	d := &net.Dialer{Timeout: httpx.PeekTimeout, Control: httpx.DialControl(allowLoopback)}
	var keys []HostKey
	seen := map[string]bool{}
	var dialErr error
	for _, algo := range scanAlgos {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			dialErr = err
			if len(keys) == 0 {
				return nil, fmt.Errorf("sshx: dial: %w", err)
			}
			break
		}
		var got ssh.PublicKey
		cfg := &ssh.ClientConfig{
			User:              "certforge",
			HostKeyAlgorithms: []string{algo},
			Timeout:           httpx.PeekTimeout,
			HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
				got = k
				return errScanDone
			},
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		_, _, _, _ = ssh.NewClientConn(conn, addr, cfg)
		stop()
		_ = conn.Close()
		if got != nil && !seen[string(got.Marshal())] {
			seen[string(got.Marshal())] = true
			keys = append(keys, HostKey{
				Type:   got.Type(),
				Line:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(got))),
				Sha256: ssh.FingerprintSHA256(got),
			})
		}
	}
	if len(keys) == 0 {
		if dialErr != nil {
			return nil, fmt.Errorf("sshx: dial: %w", dialErr)
		}
		return nil, errors.New("sshx: the server offered no host key")
	}
	return keys, nil
}
