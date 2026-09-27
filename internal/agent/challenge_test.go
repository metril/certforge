//go:build unix

package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/asn1"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metril/certforge/internal/agentproto"
)

// freeAddr returns a "127.0.0.1:<port>" for an ephemeral port that is free
// right now (briefly binding and releasing it), so tests never race on a
// fixed port.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func startChallengeServer(t *testing.T, cfg Config) *ChallengeServer {
	t.Helper()
	c := NewChallengeServer(cfg, NewFileWriter(discard), discard)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // let the listener goroutines bind
	return c
}

func TestChallengeServerHTTP01(t *testing.T) {
	addr := freeAddr(t)
	c := startChallengeServer(t, Config{HTTP01Listen: addr})
	ready := c.Present(agentproto.ChallengePresent{Token: "tok1", KeyAuth: "tok1.keyauth", Method: "http-01"})
	if ready.Error != "" {
		t.Fatalf("present: %+v", ready)
	}
	get := func(token string) (int, string) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/.well-known/acme-challenge/"+token, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("tok1"); code != http.StatusOK || body != "tok1.keyauth" {
		t.Fatalf("known token: %d %q", code, body)
	}
	if code, _ := get("nope"); code != http.StatusNotFound {
		t.Fatalf("unknown token: %d", code)
	}
	c.CleanUp(agentproto.ChallengeCleanup{Token: "tok1"})
	if code, _ := get("tok1"); code != http.StatusNotFound {
		t.Fatalf("cleaned up token: %d", code)
	}
}

func TestChallengeServerNoListenerRefusesHTTP01(t *testing.T) {
	c := NewChallengeServer(Config{}, NewFileWriter(discard), discard)
	ready := c.Present(agentproto.ChallengePresent{Token: "t", KeyAuth: "k", Method: "http-01"})
	if ready.Error == "" {
		t.Fatal("no listener and no webroot accepted")
	}
}

// idPeAcmeIdentifierV1 is RFC 8737's acmeValidation-v1 extension OID.
var idPeAcmeIdentifierV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

func TestChallengeServerTLSALPN(t *testing.T) {
	addr := freeAddr(t)
	c := startChallengeServer(t, Config{TLSALPNListen: addr})
	domain, keyAuth := "example.test", "tok2.keyauth"
	ready := c.Present(agentproto.ChallengePresent{Token: "tok2", KeyAuth: keyAuth, Domain: domain, Method: "tls-alpn-01"})
	if ready.Error != "" {
		t.Fatalf("present: %+v", ready)
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: domain, NextProtos: []string{"acme-tls/1"}}) //nolint:gosec // test dial
	if err != nil {
		t.Fatalf("dial with acme-tls/1: %v", err)
	}
	certs := conn.ConnectionState().PeerCertificates
	_ = conn.Close()
	if len(certs) != 1 {
		t.Fatalf("peer certificates: %d", len(certs))
	}
	var digest []byte
	for _, ext := range certs[0].Extensions {
		if ext.Id.Equal(idPeAcmeIdentifierV1) {
			if _, err := asn1.Unmarshal(ext.Value, &digest); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := sha256.Sum256([]byte(keyAuth))
	if len(digest) == 0 || string(digest) != string(want[:]) {
		t.Fatalf("acmeValidation-v1 digest = %x, want %x", digest, want)
	}

	// A dial without acme-tls/1 in its ALPN list is refused.
	_, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: domain, NextProtos: []string{"http/1.1"}}) //nolint:gosec // test dial
	if err == nil {
		t.Fatal("dial without acme-tls/1 accepted")
	}
}

func TestChallengeWebrootConfined(t *testing.T) {
	dir := t.TempDir()
	c := NewChallengeServer(Config{WriteAllow: []string{dir}}, NewFileWriter(discard), discard)

	outside := c.Present(agentproto.ChallengePresent{Token: "t1", KeyAuth: "k1", Method: "http-01", Webroot: "/root/not-allowed"})
	if outside.Error == "" {
		t.Fatal("webroot outside CF_WRITE_ALLOW accepted")
	}

	ready := c.Present(agentproto.ChallengePresent{Token: "t2", KeyAuth: "k2", Method: "http-01", Webroot: dir})
	if ready.Error != "" {
		t.Fatalf("present: %+v", ready)
	}
	p := filepath.Join(dir, ".well-known", "acme-challenge", "t2")
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "k2" {
		t.Fatalf("webroot file: %v %q", err, b)
	}
	c.CleanUp(agentproto.ChallengeCleanup{Token: "t2"})
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("webroot file not removed on cleanup")
	}
}
