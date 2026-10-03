//go:build integration

package agents

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/crypto/cryptotest"
)

// countingBox counts Open calls: the agent CA key is the only sealed value
// Enroll opens, so a count of zero means no CA material was decrypted.
type countingBox struct {
	cryptotest.PrefixBox
	opens atomic.Int64
}

func (b *countingBox) Open(ctx context.Context, s []byte) ([]byte, error) {
	b.opens.Add(1)
	return b.PrefixBox.Open(ctx, s)
}

func enrollCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// A bad token is refused before any CA material is decrypted, and a failure
// after the token is consumed (a non-pending client) rolls the consumption back.
func TestEnrollValidatesTokenBeforeCAMaterial(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()
	box := &countingBox{}
	f.svc.CA = agentca.NewStore(f.pool, box)
	f.svc.Settings = StaticSettings(Settings{}, "https://cf.example.test")
	e, err := f.svc.CreateClient(ctx, f.org, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := f.svc.CA.Trusted(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := agentproto.NewToken("https://cf.example.test", agentca.Fingerprint(trusted[0].Raw))
	if err != nil {
		t.Fatal(err)
	}

	box.opens.Store(0)
	_, err = f.svc.Enroll(ctx, agentproto.EnrollRequest{Token: unknown, CSR: enrollCSR(t)})
	var ae *Error
	if !errors.As(err, &ae) || ae.Kind != KindUnauthorized {
		t.Fatalf("unknown token: got %v, want unauthorized", err)
	}
	if n := box.opens.Load(); n != 0 {
		t.Fatalf("bad token opened CA material %d times", n)
	}

	// The token is valid but the client is no longer pending: the conflict
	// happens after ConsumeEnrollmentToken, which must roll back.
	if _, err := f.pool.Exec(ctx, `UPDATE clients SET status = 'revoked' WHERE id = $1`, e.Client.ID); err != nil {
		t.Fatal(err)
	}
	box.opens.Store(0)
	_, err = f.svc.Enroll(ctx, agentproto.EnrollRequest{Token: e.Token, CSR: enrollCSR(t)})
	if !errors.As(err, &ae) || ae.Kind != KindConflict {
		t.Fatalf("revoked client: got %v, want conflict", err)
	}
	if n := box.opens.Load(); n != 0 {
		t.Fatalf("non-pending client opened CA material %d times", n)
	}
	var used int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM enrollment_tokens WHERE client_id = $1 AND used_at IS NOT NULL`, e.Client.ID).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used != 0 {
		t.Fatal("a failed enrolment left its token consumed")
	}
}
