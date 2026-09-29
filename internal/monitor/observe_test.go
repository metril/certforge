package monitor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// selfSignedCert returns a real, x509-parseable self-signed certificate
// (same pattern as internal/delivery/delivery_test.go's own helper).
func selfSignedCert(t *testing.T, cn string, notAfter time.Time) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn, Organization: []string{"Test CA"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

// listenTLS starts a one-shot TLS server on 127.0.0.1 presenting leafDER/key,
// returning its port; the listener is closed on test cleanup.
func listenTLS(t *testing.T, leafDER []byte, key *ecdsa.PrivateKey) int {
	t.Helper()
	cert := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.(*tls.Conn).Handshake()
				// Hold the connection open briefly so the client has time to
				// read PeerCertificates before the server tears it down.
				time.Sleep(50 * time.Millisecond)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestObserveKnownCert(t *testing.T) {
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	leafDER, key := selfSignedCert(t, "monitor.example.test", notAfter)
	port := listenTLS(t, leafDER, key)

	obs := Observe("127.0.0.1", port, "monitor.example.test", true)
	if obs.Err != nil {
		t.Fatalf("Err = %v, want nil", obs.Err)
	}
	wantFP := sha256.Sum256(leafDER)
	if obs.Fingerprint != hex.EncodeToString(wantFP[:]) {
		t.Errorf("Fingerprint = %q, want %x", obs.Fingerprint, wantFP)
	}
	if !obs.NotAfter.Equal(notAfter.Truncate(time.Second)) && obs.NotAfter.Sub(notAfter).Abs() > time.Second {
		t.Errorf("NotAfter = %v, want ~%v", obs.NotAfter, notAfter)
	}
	if !strings.Contains(obs.Issuer, "Test CA") {
		t.Errorf("Issuer = %q, want to contain Test CA", obs.Issuer)
	}
	// Self-signed against the system pool: the chain does not verify.
	if obs.ChainError == "" {
		t.Error("ChainError = \"\", want a verification failure (self-signed, untrusted root)")
	}
}

func TestObserveUnreachable(t *testing.T) {
	// A listener bound then immediately closed frees the port with nothing
	// behind it, so the OS refuses the connection right away instead of the
	// test waiting out DialTimeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	start := time.Now()
	obs := Observe("127.0.0.1", port, "", true)
	if obs.Err == nil {
		t.Fatal("Err = nil, want a dial failure")
	}
	if elapsed := time.Since(start); elapsed > DialTimeout {
		t.Errorf("Observe took %v, want well under DialTimeout (%v)", elapsed, DialTimeout)
	}
	if obs.Fingerprint != "" {
		t.Errorf("Fingerprint = %q, want empty on an unreachable host", obs.Fingerprint)
	}
}

func TestObserveLoopbackPolicy(t *testing.T) {
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	leafDER, key := selfSignedCert(t, "loop.example.test", notAfter)
	port := listenTLS(t, leafDER, key)

	obs := Observe("127.0.0.1", port, "loop.example.test", false)
	if obs.Err == nil {
		t.Fatal("Err = nil, want the loopback host rejected before any dial")
	}
	if obs.Fingerprint != "" {
		t.Errorf("Fingerprint = %q, want empty (rejected before dialing)", obs.Fingerprint)
	}

	// allowLoopback true reaches the same host fine (sanity: the previous
	// rejection was the policy, not a broken fixture).
	obs = Observe("127.0.0.1", port, "loop.example.test", true)
	if obs.Err != nil {
		t.Fatalf("allowLoopback true: Err = %v, want nil", obs.Err)
	}
}
