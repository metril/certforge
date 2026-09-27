//go:build integration

package issuance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/fs"
	"math/big"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/importer"
)

// fakeImporter feeds ImportCertificates a canned item list instead of
// parsing a real archive, so these tests can construct exactly the
// ImportedCert shapes they need (a mismatched key, two entries claiming
// the same name) without building zip/tar fixtures.
type fakeImporter struct{ items []importer.ImportedCert }

func (f fakeImporter) Detect(fs.FS) bool { return true }
func (f fakeImporter) Import(context.Context, fs.FS) ([]importer.ImportedCert, error) {
	return f.items, nil
}

func (f *fixture) importSvc(items []importer.ImportedCert) *Service {
	return &Service{Store: f.store, Certs: certstore.New(f.pool, cryptotest.PrefixBox{}),
		Importers: []importer.Importer{fakeImporter{items: items}}}
}

// selfSigned builds a self-signed leaf certificate (DNS name cn) and its
// own PKCS#8 key, valid for 90 days from now.
func selfSigned(t *testing.T, cn string, serial int64) (leafDER, keyPKCS8 []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{cn}, NotBefore: now, NotAfter: now.AddDate(0, 3, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der, pkcs8
}

// TestImportKeyMismatch is fix-round-1 finding 1: a key file that decodes
// fine on its own but does not actually match the leaf's public key must
// not be sealed and stored — it must skip with a specific reason, the same
// check ParseUpload (upload.go) applies to an uploaded key.
func TestImportKeyMismatch(t *testing.T) {
	f := newFixture(t)
	leaf, _ := selfSigned(t, "mismatch.example.test", 1001)
	_, otherKey := selfSigned(t, "other.example.test", 1002) // a different certificate's key
	svc := f.importSvc([]importer.ImportedCert{
		{Name: "mismatch.example.test", Source: importer.SourceAcmeSh, LeafDER: leaf, KeyPKCS8: otherKey},
	})

	res, err := svc.ImportCertificates(context.Background(), f.org, f.ca.ID, fstest.MapFS{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.Items[0].Action != "skip" {
		t.Fatalf("items = %+v, want one skip", res.Items)
	}
	if res.Items[0].Reason != "key does not match the certificate" {
		t.Fatalf("reason = %q", res.Items[0].Reason)
	}

	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM certificates WHERE org_id = $1 AND name = 'mismatch.example.test'`, f.org).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("a certificate with a mismatched key was stored")
	}
}

// TestImportMissingCARejected is fix-round-1 finding 2: importOne's own
// validateDefaultsTx call (the FOR KEY SHARE lock P34 requires for a caId
// held in jsonb, added alongside CreateExternalCertificate) rejects a caId
// that does not name a CA of this org — called directly (bypassing
// ImportCertificates' own upfront, unlocked GetCA check) so this proves
// the locked, tx-scoped check added inside importOne is itself correct,
// independent of that earlier check ever running first.
func TestImportMissingCARejected(t *testing.T) {
	f := newFixture(t)
	leaf, key := selfSigned(t, "noca.example.test", 1003)
	ic := importer.ImportedCert{Name: "noca.example.test", Source: importer.SourceAcmeSh, LeafDER: leaf, KeyPKCS8: key}
	svc := f.importSvc(nil)
	badCA := uuid.New()

	_, err := svc.importOne(context.Background(), f.org, Defaults{CAID: &badCA}, RenewPolicy{Mode: RenewPercent, Value: 33}, ic, false)
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "caId" {
		t.Fatalf("err = %v, want a ValidationError on caId", err)
	}
}

// TestImportDuplicateNameInArchive is fix-round-1 finding 3: acme.sh's
// <domain>/ and <domain>_ecc/ both derive the same certificate name; dry
// run and create must report the exact same outcome for the pair (the
// first creates, the second is a "duplicate name in archive" skip) even
// though dry run's per-item transactions each roll back and so would
// otherwise never observe one another.
func TestImportDuplicateNameInArchive(t *testing.T) {
	f := newFixture(t)
	rsaLeaf, rsaKey := selfSigned(t, "dup.example.test", 1101)
	eccLeaf, eccKey := selfSigned(t, "dup.example.test", 1102)
	items := []importer.ImportedCert{
		{Name: "dup.example.test", Source: importer.SourceAcmeSh, LeafDER: rsaLeaf, KeyPKCS8: rsaKey},
		{Name: "dup.example.test", Source: importer.SourceAcmeSh, LeafDER: eccLeaf, KeyPKCS8: eccKey},
	}

	dry, err := f.importSvc(items).ImportCertificates(context.Background(), f.org, f.ca.ID, fstest.MapFS{}, true)
	if err != nil {
		t.Fatal(err)
	}
	assertDupPattern(t, "dry run", dry.Items)

	real, err := f.importSvc(items).ImportCertificates(context.Background(), f.org, f.ca.ID, fstest.MapFS{}, false)
	if err != nil {
		t.Fatal(err)
	}
	assertDupPattern(t, "create", real.Items)

	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM certificates WHERE org_id = $1 AND name = 'dup.example.test'`, f.org).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("certificates named dup.example.test = %d, want exactly 1", n)
	}
}

// TestImportInvalidName covers the spec-gap fix: a name over the 1-100
// length bound every other named resource's own DB CHECK enforces (which
// certificates.name itself lacks) skips as "invalid name" rather than
// being attempted.
func TestImportInvalidName(t *testing.T) {
	f := newFixture(t)
	longName := ""
	for i := 0; i < 101; i++ {
		longName += "a"
	}
	leaf, key := selfSigned(t, "toolong.example.test", 1201)
	svc := f.importSvc([]importer.ImportedCert{
		{Name: longName, Source: importer.SourceAcmeSh, LeafDER: leaf, KeyPKCS8: key},
	})

	res, err := svc.ImportCertificates(context.Background(), f.org, f.ca.ID, fstest.MapFS{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.Items[0].Action != "skip" || res.Items[0].Reason != "invalid name" {
		t.Fatalf("items = %+v, want a skip \"invalid name\"", res.Items)
	}
}

func assertDupPattern(t *testing.T, label string, items []ImportItem) {
	t.Helper()
	if len(items) != 2 {
		t.Fatalf("%s: items = %+v, want 2", label, items)
	}
	if items[0].Action != "create" {
		t.Fatalf("%s: items[0].Action = %q, want create", label, items[0].Action)
	}
	if items[1].Action != "skip" || items[1].Reason != "duplicate name in archive" {
		t.Fatalf("%s: items[1] = %+v, want skip \"duplicate name in archive\"", label, items[1])
	}
}
