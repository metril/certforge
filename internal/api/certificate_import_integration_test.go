//go:build integration

package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"mime/multipart"
	"testing"
	"time"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/signer"
)

// acmeShZip builds a minimal acme.sh archive in memory: one certificate
// directory (fullchain.cer, <domain>.key), the layout Task 14's importer
// package parses directly, at the archive's root.
func acmeShZip(t *testing.T, domain string, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: domain},
		DNSNames: []string{domain}, NotBefore: now, NotAfter: now.AddDate(0, 3, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writeZipFile(t, zw, domain+"/fullchain.cer", leafPEM)
	writeZipFile(t, zw, domain+"/"+domain+".key", keyPEM)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeZipFile(t *testing.T, zw *zip.Writer, name string, data []byte) {
	t.Helper()
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
}

// importBody builds the multipart/form-data body importCertificates
// expects: archive (a file part) plus caId and dryRun (plain fields).
func importBody(t *testing.T, archive []byte, caID, dryRun string) *multipart.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("archive", "backup.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(archive); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteField("caId", caID); err != nil {
		t.Fatal(err)
	}
	if dryRun != "" {
		if err := w.WriteField("dryRun", dryRun); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return multipart.NewReader(&buf, w.Boundary())
}

// seedImportCA creates a CA and an ACME account on it, the minimum
// ImportCertificates needs to accept a caId.
func (f *apiFixture) seedImportCA(t *testing.T, name string) issuance.CA {
	t.Helper()
	ctx := context.Background()
	ca, err := f.store.CreateCA(ctx, f.org, issuance.CAInput{Name: name, Preset: "custom", DirectoryURL: "https://" + name + ".test/dir", Resolvers: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	m := signer.AccountMaterial{Email: "ops@" + name + ".test", KeyPKCS8: []byte("k"), RegistrationURI: "https://" + name + ".test/acct/1"}
	if _, err := f.store.InsertAccount(ctx, f.org, ca.ID, m); err != nil {
		t.Fatal(err)
	}
	return ca
}

// certCount counts certificates by name in the fixture org, used to check a
// dry run stored nothing.
func (f *apiFixture) certCount(t *testing.T, name string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM certificates WHERE org_id = $1 AND name = $2`, f.org, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestImportDryRunThenCreate is the Task 14 brief's core coverage: a dry
// run previews without storing anything, create stores a managed
// certificate with an imported version and nextRenewAt set, a second
// create run on the same archive skips the now-taken name, and exactly one
// certificate.import audit row comes from the run that actually created
// something.
func TestImportDryRunThenCreate(t *testing.T) {
	f := newAPIFixture(t)
	op := f.as("operator")
	ca := f.seedImportCA(t, "import-ca")
	archive := acmeShZip(t, "imported.example.test", 901)

	// Dry run: previews, stores nothing.
	dry, err := f.srv.ImportCertificates(op, gen.ImportCertificatesRequestObject{OrgId: f.org,
		Body: importBody(t, archive, ca.ID.String(), "true")})
	if err != nil {
		t.Fatal(err)
	}
	dryRes, ok := dry.(gen.ImportCertificates200JSONResponse)
	if !ok {
		t.Fatalf("response type = %T", dry)
	}
	if !dryRes.DryRun {
		t.Fatal("dryRun = false, want true")
	}
	if len(dryRes.Items) != 1 || string(dryRes.Items[0].Action) != "create" {
		t.Fatalf("items = %+v", dryRes.Items)
	}
	if dryRes.Items[0].CertificateId != nil {
		t.Fatal("dry run set a certificateId")
	}
	if n := f.certCount(t, "imported.example.test"); n != 0 {
		t.Fatalf("dry run stored %d certificate rows, want 0", n)
	}

	// Create: stores it, managed, imported, nextRenewAt set, caId recorded.
	created, err := f.srv.ImportCertificates(op, gen.ImportCertificatesRequestObject{OrgId: f.org,
		Body: importBody(t, archive, ca.ID.String(), "false")})
	if err != nil {
		t.Fatal(err)
	}
	createdRes := created.(gen.ImportCertificates200JSONResponse)
	if createdRes.DryRun {
		t.Fatal("dryRun = true, want false")
	}
	if len(createdRes.Items) != 1 || string(createdRes.Items[0].Action) != "create" {
		t.Fatalf("items = %+v", createdRes.Items)
	}
	id := createdRes.Items[0].CertificateId
	if id == nil {
		t.Fatal("create did not set certificateId")
	}
	c, err := f.store.GetCertificate(context.Background(), f.org, *id)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Managed {
		t.Fatal("imported certificate is not managed")
	}
	if c.NextRenewAt == nil {
		t.Fatal("imported certificate has no nextRenewAt")
	}
	if c.Overrides.CAID == nil || *c.Overrides.CAID != ca.ID {
		t.Fatalf("overrides.caId = %v, want %s", c.Overrides.CAID, ca.ID)
	}
	if c.CurrentVersionID == nil {
		t.Fatal("no current version")
	}
	v, err := f.certs.Get(context.Background(), c.ID, *c.CurrentVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if v.Source != "imported" {
		t.Fatalf("source = %s, want imported", v.Source)
	}
	if v.CAID != nil {
		t.Fatal("an imported version's CAID must stay nil (no replaces)")
	}

	// A second create run on the same archive skips the now-taken name.
	again, err := f.srv.ImportCertificates(op, gen.ImportCertificatesRequestObject{OrgId: f.org,
		Body: importBody(t, archive, ca.ID.String(), "false")})
	if err != nil {
		t.Fatal(err)
	}
	againRes := again.(gen.ImportCertificates200JSONResponse)
	if len(againRes.Items) != 1 || string(againRes.Items[0].Action) != "skip" {
		t.Fatalf("items = %+v, want a skip", againRes.Items)
	}

	if n := f.auditCount(t, "certificate.import"); n != 1 {
		t.Fatalf("certificate.import audit rows = %d, want 1", n)
	}
}

// TestImportNoAccount covers the 422 when the org has a CA but no ACME
// account registered against it.
func TestImportNoAccount(t *testing.T) {
	f := newAPIFixture(t)
	op := f.as("operator")
	ctx := context.Background()
	ca, err := f.store.CreateCA(ctx, f.org, issuance.CAInput{Name: "no-account-ca", Preset: "custom", DirectoryURL: "https://no-account.test/dir", Resolvers: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	archive := acmeShZip(t, "noaccount.example.test", 902)

	_, err = f.srv.ImportCertificates(op, gen.ImportCertificatesRequestObject{OrgId: f.org,
		Body: importBody(t, archive, ca.ID.String(), "true")})
	wantStatus(t, err, 422)
}
