package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metril/certforge/internal/agentca"
)

// TestVerifyConnectionUsesLiveBundle covers review finding 1 (fix round 1):
// the client's TLS config must read the identity's CA pool fresh on every
// handshake, not a copy captured at NewClient time, so a rotated bundle
// (SaveBundle) applies to the next dial without rebuilding the client.
func TestVerifyConnectionUsesLiveBundle(t *testing.T) {
	f := newFakeServer(t)
	dir := t.TempDir()
	id, err := Enroll(context.Background(), dir, f.token(t), facts)
	if err != nil {
		t.Fatal(err)
	}
	cl := NewClient(id)

	conn, err := cl.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial with the real bundle: %v", err)
	}
	_ = conn.CloseNow()

	// Swap in a bundle that does not trust the fake server's CA at all.
	other, _, err := agentca.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := id.SaveBundle(agentca.CertPEM(other.Raw)); err != nil {
		t.Fatal(err)
	}
	cl.tr.CloseIdleConnections() // force a fresh handshake, not a reused connection
	if _, err := cl.Dial(context.Background()); err == nil {
		t.Fatal("dial succeeded against a bundle that does not trust the server")
	}

	// Restore the real bundle: the same Client (same Identity) trusts the
	// server again without being rebuilt.
	if err := id.SaveBundle([]byte(f.bundle)); err != nil {
		t.Fatal(err)
	}
	cl.tr.CloseIdleConnections()
	conn2, err := cl.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial should succeed once the real bundle is restored: %v", err)
	}
	_ = conn2.CloseNow()
}

// TestConcurrentRenewAndRequest covers review finding 2 (fix round 1): a
// renewal must not race with concurrent handshakes reading the identity's
// certificate and CA pool. Run with -race.
func TestConcurrentRenewAndRequest(t *testing.T) {
	f := newFakeServer(t)
	dir := t.TempDir()
	id, err := Enroll(context.Background(), dir, f.token(t), facts)
	if err != nil {
		t.Fatal(err)
	}
	cl := NewClient(id)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = cl.Assignments(context.Background())
		}
	}()

	for range 5 {
		if err := cl.Renew(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}

// TestVerifyPinnedRejectsWrongSigner covers review finding 5 (fix round 1):
// a chain that merely contains a certificate whose fingerprint matches the
// pin is not enough; the presented leaf must actually chain to it.
func TestVerifyPinnedRejectsWrongSigner(t *testing.T) {
	realCert, _, err := agentca.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	otherCert, otherKey, err := agentca.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A leaf actually signed by "other", presented alongside "real": the
	// fingerprint pin names "real", but the leaf does not chain to it.
	leaf, err := agentca.SignServer(&agentca.CA{Cert: otherCert, Key: otherKey}, &key.PublicKey, []string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = verifyPinned([][]byte{leaf.Raw, realCert.Raw}, agentca.Fingerprint(realCert.Raw))
	if err == nil || strings.Contains(err.Error(), "does not contain the CA pinned") {
		t.Fatalf("expected a chain-verification failure, got %v", err)
	}
}
