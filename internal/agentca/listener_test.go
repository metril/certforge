package agentca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeSource struct {
	ca      *CA
	trusted []*x509.Certificate
}

func (f *fakeSource) Oldest(context.Context) (*CA, error)                  { return f.ca, nil }
func (f *fakeSource) Trusted(context.Context) ([]*x509.Certificate, error) { return f.trusted, nil }

func TestReloadIssuesAndKeepsServerCert(t *testing.T) {
	ctx := context.Background()
	ca := testCA(t)
	src := &fakeSource{ca: ca, trusted: []*x509.Certificate{ca.Cert}}
	names := []string{"agents.example.test", "127.0.0.1"}
	now := now0
	l := &Listener{Source: src, Names: func(context.Context) ([]string, error) { return names, nil }, Now: func() time.Time { return now }}
	if _, ok := l.Info(); ok {
		t.Fatal("info before load")
	}
	if err := l.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	st := l.state.Load()
	info, _ := l.Info()
	if info.CAID != ca.ID || !slices.Equal(info.Names, names) || len(st.cert.Certificate) != 2 || !bytes.Equal(st.cert.Certificate[1], ca.Cert.Raw) {
		t.Fatalf("info %+v chain %d", info, len(st.cert.Certificate))
	}
	if err := l.Reload(ctx); err != nil || l.state.Load().leaf != st.leaf {
		t.Fatal("re-issued without cause")
	}
	names = []string{"other.example.test"}
	if err := l.Reload(ctx); err != nil || l.state.Load().leaf == st.leaf || l.state.Load().leaf.DNSNames[0] != "other.example.test" {
		t.Fatal("names change not re-issued")
	}
	st = l.state.Load()
	now = now0.Add(250 * 24 * time.Hour)
	if err := l.Reload(ctx); err != nil || l.state.Load().leaf == st.leaf {
		t.Fatal("not renewed past two thirds")
	}
	st = l.state.Load()
	next := testCA(t)
	src.ca, src.trusted = next, []*x509.Certificate{next.Cert} // the old CA was retired
	if err := l.Reload(ctx); err != nil || l.state.Load().leaf == st.leaf || l.state.Load().caID != next.ID {
		t.Fatal("signing CA change not re-issued")
	}
}

func TestTLSConfigVerifiesClientCerts(t *testing.T) {
	ctx := context.Background()
	fresh, freshKey, err := NewCA(time.Now()) // real time: the handshake checks validity against the clock
	if err != nil {
		t.Fatal(err)
	}
	ca := &CA{ID: uuid.New(), Cert: fresh, Key: freshKey}
	l := &Listener{Source: &fakeSource{ca: ca, trusted: []*x509.Certificate{ca.Cert}},
		Names: func(context.Context) ([]string, error) { return []string{"localhost"}, nil }}
	if err := l.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	clientCert := func(signer *CA) tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csr, err := ParseCSR(csrFor(t, key))
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := SignClient(signer, csr, uuid.New(), time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
	}
	handshake := func(certs []tls.Certificate) (int, error) {
		c1, c2 := net.Pipe()
		srv := tls.Server(c1, l.TLSConfig())
		cl := tls.Client(c2, &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: certs})
		done := make(chan struct{})
		go func() {
			defer close(done)
			if cl.Handshake() == nil {
				_, _ = io.Copy(io.Discard, cl)
			}
		}()
		err := srv.Handshake()
		n := len(srv.ConnectionState().VerifiedChains)
		_ = c1.Close()
		_ = c2.Close()
		<-done
		return n, err
	}
	if n, err := handshake([]tls.Certificate{clientCert(ca)}); err != nil || n != 1 {
		t.Fatalf("trusted client: %v chains %d", err, n)
	}
	if n, err := handshake(nil); err != nil || n != 0 {
		t.Fatalf("no client cert: %v chains %d", err, n)
	}
	foreignCert, foreignKey, _ := NewCA(time.Now())
	if _, err := handshake([]tls.Certificate{clientCert(&CA{Cert: foreignCert, Key: foreignKey})}); err == nil {
		t.Fatal("foreign client certificate accepted")
	}
}
