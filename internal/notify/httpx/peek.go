package httpx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

// PeekTimeout bounds one Peek (dial plus handshake).
const PeekTimeout = 10 * time.Second

// ParsePeekTarget turns an https:// URL or host:port (port defaults to 443)
// into a host and port. The https URL form is also what the URL policy
// (CheckURL) is run against by the caller.
func ParsePeekTarget(raw string) (host, port string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("required")
	}
	if strings.Contains(raw, "://") {
		u, perr := url.Parse(raw)
		if perr != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return "", "", errors.New("must be an https:// URL or host:port")
		}
		host, port = u.Hostname(), u.Port()
	} else {
		u, perr := url.Parse("https://" + raw)
		if perr != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" {
			return "", "", errors.New("must be an https:// URL or host:port")
		}
		host, port = u.Hostname(), u.Port()
	}
	if port == "" {
		port = "443"
	}
	return host, port, nil
}

// Peek completes a TLS handshake with host:port under the SSRF dial policy
// (DialControl) and returns the presented chain, leaf first, and whether it
// verifies against the system roots for sni (host when empty). The handshake
// itself does not verify: only the chain is wanted.
func Peek(ctx context.Context, host, port, sni string, allowLoopback bool) (chain []*x509.Certificate, verified bool, err error) {
	if sni == "" {
		sni = host
	}
	ctx, cancel := context.WithTimeout(ctx, PeekTimeout)
	defer cancel()
	d := &net.Dialer{Timeout: PeekTimeout, Control: DialControl(allowLoopback)}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, false, err
	}
	defer raw.Close()
	// Verification is deliberately off for the handshake: this reads a chain
	// the operator is deciding whether to trust.
	conn := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, false, err
	}
	chain = conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, false, errors.New("the server presented no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, verr := chain[0].Verify(x509.VerifyOptions{DNSName: sni, Intermediates: inter})
	return chain, verr == nil, nil
}
