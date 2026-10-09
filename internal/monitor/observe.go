package monitor

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/metril/certforge/internal/notify/httpx"
)

// Observation is one dial's outcome (Shared contract: internal/monitor's
// Observe). Err set means the host was unreachable (or refused the loopback
// policy): every other field is then zero. A non-empty ChainError means the
// handshake itself succeeded (Fingerprint/Issuer/NotAfter are populated)
// but the presented chain does not verify against the system root pool for
// this ServerName — recorded in an event's details, never itself a state.
type Observation struct {
	Fingerprint string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	ChainError  string
	Err         error
}

// Observe dials host:port under DialTimeout (Task 9 brief), rejecting a
// loopback/link-local/unspecified host up front the same way httpx.CheckHost
// does for a notifier destination (Deviations R5: "monitor hosts follow the
// R3 loopback/link-local policy"), then again at actual dial time via
// httpx.DialControl (DNS-rebinding parity). The handshake itself uses
// InsecureSkipVerify (ServerName sni, or host when sni is empty) only to
// capture whatever leaf the server presents; leaf.Verify against the system
// root pool then runs separately, its result going to ChainError, never
// disabling verification for anything that would actually trust the
// connection.
func Observe(host string, port int, sni string, allowLoopback bool) Observation {
	if err := httpx.CheckHost(host, allowLoopback); err != nil {
		return Observation{Err: err}
	}
	serverName := sni
	if serverName == "" {
		serverName = host
	}
	dialer := &net.Dialer{Timeout: DialTimeout, Control: httpx.DialControl(allowLoopback)}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // capture-only handshake; leaf.Verify below is the real check
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return Observation{Err: err}
	}
	defer func() { _ = conn.Close() }()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return Observation{Err: errors.New("monitor: no certificate presented")}
	}
	leaf := certs[0]
	fp := sha256.Sum256(leaf.Raw)
	obs := Observation{
		Fingerprint: hex.EncodeToString(fp[:]),
		Issuer:      leaf.Issuer.String(),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: serverName, Roots: pool, Intermediates: intermediates}); err != nil {
		obs.ChainError = err.Error()
	}
	return obs
}
