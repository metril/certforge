//go:build integration

package issuance

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/signer"
)

// cancelOnRevoke is a signer whose Revoke succeeds but cancels the request
// context first, like a client that disconnects while Vault is revoking.
type cancelOnRevoke struct {
	signer.Signer
	cancel context.CancelFunc
}

func (c cancelOnRevoke) Revoke(context.Context, *x509.Certificate, int) error {
	c.cancel()
	return nil
}

// TestRevokeVaultVersionRecordsAfterCancel: the revoked_at write survives a
// request context cancelled after the Vault call.
func TestRevokeVaultVersionRecordsAfterCancel(t *testing.T) {
	f := newFixture(t)
	names := []string{"cancel.example.test"}
	c := f.cert(t, names, nil)
	iss := issuedFor(t, names, now0)
	bg := context.Background()
	tx, err := f.store.Begin(bg)
	if err != nil {
		t.Fatal(err)
	}
	v, err := certstore.New(f.pool, cryptotest.PrefixBox{}).Insert(bg, tx, c.ID, iss, "ec256", certstore.InsertOpts{Source: "issued", CAID: &f.ca.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(bg); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(iss.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	got, err := f.store.revokeVaultVersion(ctx, cancelOnRevoke{cancel: cancel}, leaf, c.ID, v.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil {
		t.Fatal("revokedAt not set")
	}
	var n int
	if err := f.pool.QueryRow(bg, `SELECT count(*) FROM certificate_versions WHERE id = $1 AND revoked_at IS NOT NULL`, v.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("recorded rows = %d, err = %v", n, err)
	}
}
