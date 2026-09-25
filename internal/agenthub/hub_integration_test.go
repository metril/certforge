//go:build integration

package agenthub

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// signedLeaf issues a client certificate for id from ca, the same shape
// agent enrolment produces.
func signedLeaf(t *testing.T, ca *agentca.CA, id uuid.UUID) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := agentca.SignClient(ca, csr, id, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// TestServeVerifyClosesRevokedClient exercises the real re-check Serve runs
// right after registering a connection: agent_ws.go builds verify from
// agents.Service.Authenticate against the TLS leaf cert, so a client
// revoked between the HTTP handshake's own check and Serve registering the
// socket must not stay connected. Here the client is already revoked (in a
// real server this is the race window; the mechanism under test is the
// same either way) before Serve ever runs.
func TestServeVerifyClosesRevokedClient(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	org := dbtest.Org(t, pool)
	store := agentca.NewStore(pool, cryptotest.PrefixBox{})
	if _, err := store.EnsureActive(ctx); err != nil {
		t.Fatal(err)
	}
	ca, err := store.Active(ctx)
	if err != nil {
		t.Fatal(err)
	}
	svc := &agents.Service{Pool: pool, Q: q, CA: store, Settings: agents.StaticSettings(agents.Settings{}, "https://cf.example.test")}
	en, err := svc.CreateClient(ctx, org, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf := signedLeaf(t, ca, en.Client.ID)
	notAfter := leaf.NotAfter
	if _, err := q.ActivateClient(ctx, sqlcgen.ActivateClientParams{ID: en.Client.ID, AgentCertSerial: agentca.SerialHex(leaf),
		AgentCertNotAfter: &notAfter, AgentCaID: &ca.ID, Hostname: "host-1", Os: "linux", Arch: "amd64", AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, leaf); err != nil {
		t.Fatalf("sanity: newly active client should authenticate: %v", err)
	}
	if _, err := svc.RevokeClient(ctx, org, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	verify := func(vctx context.Context) error {
		_, err := svc.Authenticate(vctx, leaf)
		return err
	}
	h, s := New(nil), newFakeSession()
	done := make(chan error, 1)
	go func() {
		done <- h.Serve(ctx, en.Client.ID, s, helloHandler{got: make(chan agentproto.Message, 1)}, verify)
	}()
	if code := s.closeCode(t); code != agentproto.CloseRevoked {
		t.Fatalf("code %d", code)
	}
	<-done
	if h.Connected(en.Client.ID) {
		t.Fatal("still connected after the re-check rejected a revoked client")
	}
}
