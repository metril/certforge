//go:build integration

package issuance

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/riverqueue/river"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto/cryptotest"
)

// TestLocalCAIssueEndToEnd (Task 9 acceptance): a certificate with no
// verification rules, whose effective CA is a freshly created localca root,
// issues through the ordinary river entrypoint (IssueWorker.Work, not a
// direct SignerFactory/Issue call) and lands active with a leaf that
// verifies against the CA's own trust bundle and a stored private key.
func TestLocalCAIssueEndToEnd(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ca, err := f.store.CreateCA(ctx, f.org, CAInput{Name: "Local Root", Type: CATypeLocalCA,
		Config: map[string]any{"subject": map[string]any{"commonName": "Test Root"}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.store.CreateCertificate(ctx, f.org, CertInput{Name: "localca-leaf", CommonName: "localca-leaf.example.test",
		Overrides: Defaults{CAID: &ca.ID}})
	if err != nil {
		t.Fatal(err)
	}

	certs := certstore.New(f.pool, cryptotest.PrefixBox{})
	w := NewIssueWorker(f.store, certs)
	w.Now = func() time.Time { return now0 }
	w.Rand = func() float64 { return 0.5 }
	w.NewSigner = (&SignerFactory{Store: f.store, BaseURL: func(context.Context) string { return "" }}).New

	if err := w.Work(ctx, &river.Job[IssueArgs]{Args: IssueArgs{CertID: c.ID}}); err != nil {
		t.Fatal(err)
	}

	got, err := f.store.GetCertificate(ctx, f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusActive || got.CurrentVersionID == nil {
		t.Fatalf("cert = %+v", got)
	}
	v, err := certs.Get(ctx, c.ID, *got.CurrentVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if !v.HasKey {
		t.Fatal("version has no stored key")
	}
	m, err := certs.Material(ctx, c.ID, *got.CurrentVersionID, false)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(m.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(ca.TrustBundlePEM)) {
		t.Fatal("could not parse CA trust bundle")
	}
	// The trust bundle is the root only (localCACRUDMatrix's own
	// "generate" case); the leaf chains up to it through the issuing
	// certificate, stored alongside the leaf as m.ChainDER.
	inters := x509.NewCertPool()
	for _, der := range m.ChainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		inters.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("leaf did not verify against the CA trust bundle: %v", err)
	}
}
