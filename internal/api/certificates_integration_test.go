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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/signer"
)

func (f *apiFixture) download(ctx context.Context, c gen.Id, v gen.VersionId, parts string) (gen.DownloadCertificateVersionResponseObject, error) {
	return f.srv.DownloadCertificateVersion(ctx, gen.DownloadCertificateVersionRequestObject{OrgId: f.org, Id: c, Vid: v,
		Params: gen.DownloadCertificateVersionParams{Parts: parts}})
}

func (f *apiFixture) downloadFormat(ctx context.Context, c gen.Id, v gen.VersionId, format, parts string) (gen.DownloadCertificateVersionResponseObject, error) {
	ff := gen.DownloadCertificateVersionParamsFormat(format)
	return f.srv.DownloadCertificateVersion(ctx, gen.DownloadCertificateVersionRequestObject{OrgId: f.org, Id: c, Vid: v,
		Params: gen.DownloadCertificateVersionParams{Format: &ff, Parts: parts}})
}

func (f *apiFixture) export(ctx context.Context, c gen.Id, v gen.VersionId, body *gen.ExportRequest) (gen.ExportCertificateVersionResponseObject, error) {
	return f.srv.ExportCertificateVersion(ctx, gen.ExportCertificateVersionRequestObject{OrgId: f.org, Id: c, Vid: v, Body: body})
}

// realCert returns a real, x509-parseable self-signed leaf and one chain
// certificate, plus a PKCS#8 EC key: unlike issuedCert's opaque "leaf"/"key"
// placeholder bytes (fine for PEM, which treats parts as opaque), the
// DER/PKCS12/JKS renderers parse their input, so these tests need material
// that actually decodes.
func realCert(t *testing.T, cn string, serial int64) ([]byte, [][]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: now, NotAfter: now.AddDate(0, 3, 0), DNSNames: []string{cn}}
	leafDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	chainTpl := &x509.Certificate{SerialNumber: big.NewInt(serial + 1000), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: now, NotAfter: now.AddDate(0, 3, 0)}
	chainDER, err := x509.CreateCertificate(rand.Reader, chainTpl, chainTpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return leafDER, [][]byte{chainDER}, pkcs8
}

// realIssuedCert stores a certificate whose current version holds real,
// parseable material (see realCert); withKey=false stores a keyless
// version, the same shape an unmanaged upload without a key would leave
// (Task 13), covering ErrNoKey for DER/export.
func (f *apiFixture) realIssuedCert(t *testing.T, name string, withKey bool) (issuance.Certificate, certstore.Version) {
	t.Helper()
	ctx := context.Background()
	c, err := f.store.CreateCertificate(ctx, f.org, issuance.CertInput{Name: name, CommonName: name + ".example.test"})
	if err != nil {
		t.Fatal(err)
	}
	leafDER, chainDER, pkcs8 := realCert(t, name+".example.test", time.Now().UnixNano())
	iss := &signer.Issued{LeafDER: leafDER, ChainDER: chainDER, NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour), Serial: "0b"}
	if withKey {
		iss.PrivateKeyPKCS8 = pkcs8
	}
	tx, err := f.store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.certs.Insert(ctx, tx, c.ID, iss, "ec256", certstore.InsertOpts{Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return c, v
}

// TestDownloadDER is the Task 4 brief's DER download coverage: a single
// part returns octet-stream bytes that parse as x509, several parts zip
// (named cert.der/chain-1.der, matching the DER renderer's own file names),
// and a PEM-only part (fullchain) is 422 through render.ErrNotDER.
func TestDownloadDER(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.realIssuedCert(t, "web-der", true)

	res, err := f.downloadFormat(f.as("operator"), c.ID, v.ID, "der", "cert")
	if err != nil {
		t.Fatal(err)
	}
	octet, ok := res.(gen.DownloadCertificateVersion200ApplicationoctetStreamResponse)
	if !ok {
		t.Fatalf("response type = %T", res)
	}
	body, _ := io.ReadAll(octet.Body)
	if _, err := x509.ParseCertificate(body); err != nil {
		t.Fatalf("cert.der did not parse: %v", err)
	}

	res, err = f.downloadFormat(f.as("operator"), c.ID, v.ID, "der", "cert,chain")
	if err != nil {
		t.Fatal(err)
	}
	z, ok := res.(gen.DownloadCertificateVersion200ApplicationzipResponse)
	if !ok {
		t.Fatalf("response type = %T", res)
	}
	b, _ := io.ReadAll(z.Body)
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, zf := range zr.File {
		names[zf.Name] = true
	}
	if !names["cert.der"] || !names["chain-1.der"] {
		t.Fatalf("zip entries = %v", names)
	}

	_, err = f.downloadFormat(f.as("operator"), c.ID, v.ID, "der", "fullchain")
	wantStatus(t, err, http.StatusUnprocessableEntity)

	// Review fix round 1: the der key part is audited with format "der",
	// same as pem's key/combined parts are audited with format "pem"
	// (TestDownloadKeyAuditedForAdmin).
	res, err = f.downloadFormat(f.as("admin"), c.ID, v.ID, "der", "key")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.(gen.DownloadCertificateVersion200ApplicationoctetStreamResponse); !ok {
		t.Fatalf("key response type = %T", res)
	}
	var format string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT details->>'format' FROM audit_events WHERE action = 'certificate.key_exported' ORDER BY id DESC LIMIT 1`).Scan(&format); err != nil {
		t.Fatal(err)
	}
	if format != "der" {
		t.Fatalf("audit format = %q, want der", format)
	}
}

// TestDownloadRejectsContainerFormats is the review fix-round-1 coverage for
// the critical finding: DownloadCertificateVersion must reject format=p12
// and format=jks itself (422) rather than pass them to render.For, which
// would otherwise accept them, decrypt the stored key for a request that
// can never succeed (the download endpoint has no password field), and
// only then fail inside the renderer. Rejected up front, no audit row is
// ever written for these.
func TestDownloadRejectsContainerFormats(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.realIssuedCert(t, "web-container", true)
	for _, format := range []string{"p12", "jks"} {
		_, err := f.downloadFormat(f.as("admin"), c.ID, v.ID, format, "key")
		wantStatus(t, err, http.StatusUnprocessableEntity)
		// The rejection must be format-level (rejected before ever calling
		// render.For/Material), not a password/parts error surfacing later
		// from inside the p12/jks renderer.
		if !strings.Contains(err.Error(), "Invalid format") {
			t.Fatalf("format=%s error = %v, want an Invalid format problem", format, err)
		}
	}
	if n := f.auditCount(t, "certificate.key_exported"); n != 0 {
		t.Fatalf("rejected container-format download recorded %d exports", n)
	}
}

// TestExportDeniedWritesNoAudit is the review fix-round-1 coverage: a
// caller without keys:export is refused before Material or Auditor.Record
// is ever reached, so a denied export leaves no certificate.key_exported
// row.
func TestExportDeniedWritesNoAudit(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.realIssuedCert(t, "web-denied", true)
	pw := "hunter22"
	_, err := f.export(f.as("viewer"), c.ID, v.ID, &gen.ExportRequest{Format: gen.ExportFormatP12, Password: &pw})
	wantStatus(t, err, http.StatusForbidden)
	if n := f.auditCount(t, "certificate.key_exported"); n != 0 {
		t.Fatalf("denied export recorded %d exports", n)
	}
}

// TestExportEncodingAndAliasFieldRestrictions is the review fix-round-1
// coverage for the two Minor findings: encoding only applies to p12, alias
// only to jks (each 422 on the offending field otherwise), and an unknown
// encoding value is 422 encoding rather than a raw renderer error.
func TestExportEncodingAndAliasFieldRestrictions(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.realIssuedCert(t, "web-fields", true)
	pw := "hunter22"

	legacy := gen.P12Encoding("legacy")
	_, err := f.export(f.as("admin"), c.ID, v.ID, &gen.ExportRequest{Format: gen.ExportFormatJks, Password: &pw, Encoding: &legacy})
	wantStatus(t, err, http.StatusUnprocessableEntity)

	alias := "my-alias"
	_, err = f.export(f.as("admin"), c.ID, v.ID, &gen.ExportRequest{Format: gen.ExportFormatP12, Password: &pw, Alias: &alias})
	wantStatus(t, err, http.StatusUnprocessableEntity)

	bogus := gen.P12Encoding("bogus")
	_, err = f.export(f.as("admin"), c.ID, v.ID, &gen.ExportRequest{Format: gen.ExportFormatP12, Password: &pw, Encoding: &bogus})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

// TestExportCorruptMaterialIs500 is the review fix-round-1 coverage for the
// other half of the encoding-validation Minor finding: once encoding is
// validated in the handler, a renderer failure that isn't ErrNoKey or
// ErrPassword (here, stored leaf DER that fails to parse — corrupt stored
// material, not caller input) must surface as 500, not 422.
func TestExportCorruptMaterialIs500(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.realIssuedCert(t, "web-corrupt", true)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE certificate_versions SET leaf_der = 'not-a-certificate' WHERE id = $1`, v.ID); err != nil {
		t.Fatal(err)
	}
	pw := "hunter22"
	// A plain (non-HTTPError) error here is what s.responseError turns into
	// a 500 at the real HTTP layer (TestDownloadKeyAuditedForAdmin's broken-
	// auditor case checks the same way, calling the handler directly rather
	// than through HTTP); problemStatus returns 0 for anything that isn't
	// an *HTTPError.
	_, err := f.export(f.as("admin"), c.ID, v.ID, &gen.ExportRequest{Format: gen.ExportFormatP12, Password: &pw})
	if err == nil || problemStatus(err) != 0 {
		t.Fatalf("want a plain (500) error, got %v", err)
	}
}

// TestExportP12 is the Task 4 brief's PKCS#12 export coverage: a caller
// without keys:export is forbidden, an authorized caller gets a decodable
// .p12 named after the certificate.
func TestExportP12(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.realIssuedCert(t, "web-p12", true)
	pw := "hunter22"

	_, err := f.export(f.as("viewer"), c.ID, v.ID, &gen.ExportRequest{Format: gen.ExportFormatP12, Password: &pw})
	wantStatus(t, err, http.StatusForbidden)

	res, err := f.export(f.as("admin"), c.ID, v.ID, &gen.ExportRequest{Format: gen.ExportFormatP12, Password: &pw})
	if err != nil {
		t.Fatal(err)
	}
	p12, ok := res.(gen.ExportCertificateVersion200ApplicationxPkcs12Response)
	if !ok {
		t.Fatalf("response type = %T", res)
	}
	if p12.Headers.ContentDisposition != `attachment; filename="web-p12.p12"` {
		t.Fatalf("content-disposition = %q", p12.Headers.ContentDisposition)
	}
	body, _ := io.ReadAll(p12.Body)
	if _, _, _, err := pkcs12.DecodeChain(body, pw); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

// TestExportJKS is the Task 4 brief's JKS export coverage: the alias
// defaults to SafeName(cert name), and a password under 6 characters is
// 422 (render.ErrPassword, JKS's own minimum).
func TestExportJKS(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.realIssuedCert(t, "web-jks", true)
	pw := "hunter22"

	res, err := f.export(f.as("admin"), c.ID, v.ID, &gen.ExportRequest{Format: gen.ExportFormatJks, Password: &pw})
	if err != nil {
		t.Fatal(err)
	}
	jr, ok := res.(gen.ExportCertificateVersion200ApplicationxJavaKeystoreResponse)
	if !ok {
		t.Fatalf("response type = %T", res)
	}
	if jr.Headers.ContentDisposition != `attachment; filename="web-jks.jks"` {
		t.Fatalf("content-disposition = %q", jr.Headers.ContentDisposition)
	}
	body, _ := io.ReadAll(jr.Body)
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(body), []byte(pw)); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.GetPrivateKeyEntry("web-jks", []byte(pw)); err != nil {
		t.Fatalf("alias did not default to SafeName(cert name): %v", err)
	}

	short := "abcde"
	_, err = f.export(f.as("admin"), c.ID, v.ID, &gen.ExportRequest{Format: gen.ExportFormatJks, Password: &short})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

// TestExportAuditOmitsPassword is the Task 4 brief's audit coverage: the
// key-export audit event names the format but never carries the password,
// under any key or as a substring of any value.
func TestExportAuditOmitsPassword(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.realIssuedCert(t, "web-audit", true)
	pw := "hunter22-not-logged"

	if _, err := f.export(f.as("admin"), c.ID, v.ID, &gen.ExportRequest{Format: gen.ExportFormatP12, Password: &pw}); err != nil {
		t.Fatal(err)
	}

	var details string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT details::text FROM audit_events WHERE action = 'certificate.key_exported' ORDER BY id DESC LIMIT 1`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, pw) {
		t.Fatalf("audit details contain the password: %s", details)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(details), &got); err != nil {
		t.Fatal(err)
	}
	if got["format"] != "p12" {
		t.Fatalf("format = %v", got["format"])
	}
	for k, val := range got {
		if strings.Contains(k, "password") || strings.Contains(fmt.Sprint(val), pw) {
			t.Fatalf("audit details key %q leaked the password: %v", k, val)
		}
	}
}

// TestExportKeylessVersion is the Task 4 brief's keyless coverage: a
// version stored with no key (the same shape an unmanaged upload without a
// key leaves, Task 13) is 404 for both export and DER's key part.
func TestExportKeylessVersion(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.realIssuedCert(t, "web-nokey", false)
	pw := "hunter22"

	_, err := f.export(f.as("admin"), c.ID, v.ID, &gen.ExportRequest{Format: gen.ExportFormatP12, Password: &pw})
	wantStatus(t, err, http.StatusNotFound)

	_, err = f.downloadFormat(f.as("admin"), c.ID, v.ID, "der", "key")
	wantStatus(t, err, http.StatusNotFound)
}

// Review Focus: downloading a key without keys:export.
func TestDownloadKeyRequiresKeysExport(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.issuedCert(t, "web")
	for _, parts := range []string{"key", "fullchain,key", "combined"} {
		_, err := f.download(f.as("operator"), c.ID, v.ID, parts)
		wantStatus(t, err, http.StatusForbidden)
	}
	if n := f.auditCount(t, "certificate.key_exported"); n != 0 {
		t.Fatalf("denied download recorded %d exports", n)
	}
	res, err := f.download(f.as("operator"), c.ID, v.ID, "fullchain")
	if err != nil {
		t.Fatal(err)
	}
	pemRes := res.(gen.DownloadCertificateVersion200ApplicationxPemFileResponse)
	body, _ := io.ReadAll(pemRes.Body)
	if bytes.Contains(body, []byte("PRIVATE KEY")) || pemRes.Headers.ContentDisposition != `attachment; filename="web-fullchain.pem"` {
		t.Fatalf("fullchain response wrong: %q %s", pemRes.Headers.ContentDisposition, body)
	}
}

func TestDownloadKeyAuditedForAdmin(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.issuedCert(t, "web")
	res, err := f.download(f.as("admin"), c.ID, v.ID, "fullchain,key")
	if err != nil {
		t.Fatal(err)
	}
	z := res.(gen.DownloadCertificateVersion200ApplicationzipResponse)
	b, _ := io.ReadAll(z.Body)
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil || len(zr.File) != 2 {
		t.Fatalf("zip: %v %v", err, zr)
	}
	if n := f.auditCount(t, "certificate.key_exported"); n != 1 {
		t.Fatalf("audit rows = %d", n)
	}
	var format string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT details->>'format' FROM audit_events WHERE action = 'certificate.key_exported' ORDER BY id DESC LIMIT 1`).Scan(&format); err != nil {
		t.Fatal(err)
	}
	if format != "pem" {
		t.Fatalf("audit format = %q, want pem", format)
	}
	broken, err := pgxpool.New(context.Background(), dbtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	broken.Close() // every audit write now fails
	f.srv.d.Auditor = audit.New(broken, bytes.Repeat([]byte{5}, 32))
	if _, err := f.download(f.as("admin"), c.ID, v.ID, "key"); err == nil || problemStatus(err) != 0 {
		t.Fatalf("key must not be released when auditing fails: %v", err)
	}
}

func TestDownloadRejectsUnknownPartAndForeignVersion(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.issuedCert(t, "web")
	other, _ := f.issuedCert(t, "api")
	_, err := f.download(f.as("viewer"), c.ID, v.ID, "cert,p12")
	wantStatus(t, err, http.StatusUnprocessableEntity)
	_, err = f.download(f.as("viewer"), other.ID, v.ID, "cert")
	wantStatus(t, err, http.StatusNotFound)
}

// Fix wave item 14: an authorization/tenancy matrix for the certificate
// handlers — viewer is denied every write/issue action, operator is denied
// a key-bearing download, and a certificate or version id belonging to
// another org is reported 404 (never exposed, never silently reinterpreted
// under the caller's own org) — plus a spot-check of the update, delete and
// versions response shapes.
func TestCertificateAuthorizationMatrix(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.issuedCert(t, "web")

	// viewer is read-only: every write/issue action is 403.
	_, err := f.srv.CreateCertificate(f.as("viewer"), gen.CreateCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateInput{Name: "x", CommonName: "x.example.test"}})
	wantStatus(t, err, http.StatusForbidden)
	_, err = f.srv.UpdateCertificate(f.as("viewer"), gen.UpdateCertificateRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.CertificateInput{Name: c.Name, CommonName: c.CommonName}})
	wantStatus(t, err, http.StatusForbidden)
	_, err = f.srv.DeleteCertificate(f.as("viewer"), gen.DeleteCertificateRequestObject{OrgId: f.org, Id: c.ID})
	wantStatus(t, err, http.StatusForbidden)
	_, err = f.srv.RenewCertificate(f.as("viewer"), gen.RenewCertificateRequestObject{OrgId: f.org, Id: c.ID})
	wantStatus(t, err, http.StatusForbidden)
	_, err = f.srv.ConfirmManualDNS(f.as("viewer"), gen.ConfirmManualDNSRequestObject{OrgId: f.org, Id: c.ID})
	wantStatus(t, err, http.StatusForbidden)

	// operator can write/issue, but not export a key-bearing download.
	_, err = f.download(f.as("operator"), c.ID, v.ID, "key")
	wantStatus(t, err, http.StatusForbidden)
	_, err = f.download(f.as("operator"), c.ID, v.ID, "combined")
	wantStatus(t, err, http.StatusForbidden)

	// A certificate or version id from another org is reported 404, never a
	// dangling reference or another org's data.
	foreignOrg := dbtest.Org(t, f.pool)
	foreign, err := f.store.CreateCertificate(context.Background(), foreignOrg,
		issuance.CertInput{Name: "foreign", CommonName: "foreign.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.srv.GetCertificate(f.as("operator"), gen.GetCertificateRequestObject{OrgId: f.org, Id: foreign.ID})
	wantStatus(t, err, http.StatusNotFound)
	_, err = f.srv.UpdateCertificate(f.as("operator"), gen.UpdateCertificateRequestObject{OrgId: f.org, Id: foreign.ID,
		Body: &gen.CertificateInput{Name: "foreign", CommonName: "foreign.example.test"}})
	wantStatus(t, err, http.StatusNotFound)
	_, err = f.srv.DeleteCertificate(f.as("operator"), gen.DeleteCertificateRequestObject{OrgId: f.org, Id: foreign.ID})
	wantStatus(t, err, http.StatusNotFound)
	_, err = f.download(f.as("operator"), foreign.ID, v.ID, "cert")
	wantStatus(t, err, http.StatusNotFound)
	_, err = f.download(f.as("operator"), c.ID, uuid.New(), "cert") // unknown version id
	wantStatus(t, err, http.StatusNotFound)

	// Update, versions and delete response shapes.
	up, err := f.srv.UpdateCertificate(f.as("operator"), gen.UpdateCertificateRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.CertificateInput{Name: "web2", CommonName: c.CommonName}})
	if err != nil {
		t.Fatal(err)
	}
	// issuedCert stores a version directly (bypassing the worker's
	// MarkCertificateIssued), so the certificate row's own current_version_id
	// is never set; this checks the identifying/renamed fields the update
	// actually changed, not a current-version link issuedCert never created.
	uc := up.(gen.UpdateCertificate200JSONResponse)
	if uc.Id != c.ID || uc.Name != "web2" || uc.CommonName != c.CommonName {
		t.Fatalf("update response = %+v", uc)
	}

	vs, err := f.srv.ListCertificateVersions(f.as("operator"), gen.ListCertificateVersionsRequestObject{OrgId: f.org, Id: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	list := vs.(gen.ListCertificateVersions200JSONResponse)
	if len(list) != 1 || list[0].Id != v.ID || list[0].Serial != v.Serial || list[0].Sha256Fingerprint != v.SHA256 {
		t.Fatalf("versions response = %+v", list)
	}

	del, err := f.srv.DeleteCertificate(f.as("operator"), gen.DeleteCertificateRequestObject{OrgId: f.org, Id: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := del.(gen.DeleteCertificate204Response); !ok {
		t.Fatalf("delete response = %+v", del)
	}
	_, err = f.srv.GetCertificate(f.as("operator"), gen.GetCertificateRequestObject{OrgId: f.org, Id: c.ID})
	wantStatus(t, err, http.StatusNotFound)
}

func TestDeleteCertificateRefusedWhileMonitorExpectsIt(t *testing.T) {
	f := newAPIFixture(t)
	c, _ := f.issuedCert(t, "web")
	var monID uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO external_monitors (org_id, name, host, expected_cert_id) VALUES ($1, 'edge', 'example.test', $2) RETURNING id`, f.org, c.ID).Scan(&monID); err != nil {
		t.Fatal(err)
	}
	_, err := f.srv.DeleteCertificate(f.as("operator"), gen.DeleteCertificateRequestObject{OrgId: f.org, Id: c.ID})
	wantStatus(t, err, http.StatusConflict)
	var he *HTTPError
	if !errors.As(err, &he) || !strings.Contains(he.Detail, "edge ("+monID.String()+")") {
		t.Fatalf("409 does not name the monitor: %v", err)
	}
	if _, err := f.srv.GetCertificate(f.as("operator"), gen.GetCertificateRequestObject{OrgId: f.org, Id: c.ID}); err != nil {
		t.Fatalf("certificate was deleted: %v", err)
	}
	if _, err := f.pool.Exec(context.Background(), `DELETE FROM external_monitors WHERE id = $1`, monID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.DeleteCertificate(f.as("operator"), gen.DeleteCertificateRequestObject{OrgId: f.org, Id: c.ID}); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmManualDnsNothingWaiting(t *testing.T) {
	f := newAPIFixture(t)
	c, _ := f.issuedCert(t, "web")
	_, err := f.srv.ConfirmManualDNS(f.as("operator"), gen.ConfirmManualDNSRequestObject{OrgId: f.org, Id: c.ID})
	wantStatus(t, err, http.StatusConflict)
}

func TestCreateCertificateAndRenew(t *testing.T) {
	f := newAPIFixture(t)
	sans := []string{"*.example.test"}
	res, err := f.srv.CreateCertificate(f.as("operator"), gen.CreateCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateInput{Name: "wild", CommonName: "example.test", Sans: &sans}})
	if err != nil {
		t.Fatal(err)
	}
	c := res.(gen.CreateCertificate201JSONResponse)
	if c.Status != "pending" || c.Effective.KeyType == nil || c.Effective.KeyType.Value != "ec256" || len(c.Sans) != 1 {
		t.Fatalf("created = %+v", c)
	}
	if n := f.auditCount(t, "certificate.create"); n != 1 {
		t.Fatalf("audit rows = %d", n)
	}
	r, err := f.srv.RenewCertificate(f.as("operator"), gen.RenewCertificateRequestObject{OrgId: f.org, Id: c.Id})
	if err != nil {
		t.Fatal(err)
	}
	if r.(gen.RenewCertificate202JSONResponse).Enqueued {
		t.Fatal("create already enqueued; renew must report a duplicate")
	}
	_, err = f.srv.RenewCertificate(f.as("viewer"), gen.RenewCertificateRequestObject{OrgId: f.org, Id: c.Id})
	wantStatus(t, err, http.StatusForbidden)
	bad := []string{"a.*.example.test"}
	_, err = f.srv.CreateCertificate(f.as("operator"), gen.CreateCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateInput{Name: "bad", CommonName: "example.test", Sans: &bad}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

// TestCreateCertificateRejectsWildcardHTTP01 (fix round 1, Minor finding):
// a wildcard SAN whose only matching rule uses http-01 is rejected at
// create time (issuance.validateWildcardMethods, wired into
// Service.CreateCertificate before the store write) with a 422 naming
// verificationRules, not left to fail only once an issuance attempt runs.
func TestCreateCertificateRejectsWildcardHTTP01(t *testing.T) {
	f := newAPIFixture(t)
	sans := []string{"*.example.test"}
	_, err := f.srv.CreateCertificate(f.as("operator"), gen.CreateCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateInput{Name: "wild-http01", CommonName: "example.test", Sans: &sans,
			VerificationRules: &[]gen.VerificationRule{{Match: "*.example.test", Method: "http-01"}}}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
	var he *HTTPError
	if !errors.As(err, &he) || he.Title != "Invalid verificationRules" {
		t.Fatalf("err = %v, want an Invalid verificationRules problem", err)
	}
}

// insertClient adds a client row directly (bypassing internal/agents,
// which certificate creation must not need for this check).
func insertClient(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, name string, capabilities []string) uuid.UUID {
	t.Helper()
	if capabilities == nil {
		capabilities = []string{}
	}
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO clients (org_id, name, status, capabilities) VALUES ($1, $2, 'active', $3) RETURNING id`,
		org, name, capabilities).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestRuleClientChecks (Task 7): a rule's clientId must belong to the
// caller's org and, unless it is an http-01 rule with its own webroot, the
// client must report the rule's challenge capability — Task 6 only parsed
// via/clientId/webroot; nothing yet stopped an operator writing via: agent
// or tls-alpn-01 against a client that could never serve it.
func TestRuleClientChecks(t *testing.T) {
	f := newAPIFixture(t)
	otherOrg := dbtest.Org(t, f.pool)
	foreign := insertClient(t, f.pool, otherOrg, "foreign", []string{"http-01"})
	noCap := insertClient(t, f.pool, f.org, "web-1", nil)
	hasTLS := insertClient(t, f.pool, f.org, "web-2", []string{"tls-alpn-01"})
	via := gen.ChallengeViaAgent

	create := func(name string, r gen.VerificationRule) error {
		_, err := f.srv.CreateCertificate(f.as("operator"), gen.CreateCertificateRequestObject{OrgId: f.org,
			Body: &gen.CertificateInput{Name: name, CommonName: name + ".example.test", VerificationRules: &[]gen.VerificationRule{r}}})
		return err
	}

	err := create("a", gen.VerificationRule{Match: "a.example.test", Method: "http-01", Via: &via, ClientId: &foreign})
	wantStatus(t, err, http.StatusUnprocessableEntity)
	var he *HTTPError
	if !errors.As(err, &he) || !strings.Contains(he.Detail, "client not found in this org") {
		t.Fatalf("foreign client detail = %v", err)
	}

	err = create("b", gen.VerificationRule{Match: "b.example.test", Method: "http-01", Via: &via, ClientId: &noCap})
	wantStatus(t, err, http.StatusUnprocessableEntity)
	if !errors.As(err, &he) || !strings.Contains(he.Detail, "client web-1 does not serve http-01") {
		t.Fatalf("missing capability detail = %v", err)
	}

	webroot := "/var/www/.well-known/acme-challenge"
	if err := create("c", gen.VerificationRule{Match: "c.example.test", Method: "http-01", Via: &via, ClientId: &noCap, Webroot: &webroot}); err != nil {
		t.Fatalf("http-01 with its own webroot: %v", err)
	}

	if err := create("d", gen.VerificationRule{Match: "d.example.test", Method: "tls-alpn-01", ClientId: &hasTLS}); err != nil {
		t.Fatalf("tls-alpn-01 with the capability: %v", err)
	}
}

// TestListCertificatesPagesAndFilters exercises the list endpoint's paging,
// status filter and sort, and is also the Review Focus for the N+1 fix: it
// only asserts on shape and ordering, but a regression back to one query
// per certificate would still pass this test correctly, just slower - the
// N+1 avoidance itself is verified by reading the code (GlobalDefaults,
// OrgDefaults and Certs.Versions are each called once per request, not once
// per certificate).
func TestListCertificatesPagesAndFilters(t *testing.T) {
	f := newAPIFixture(t)
	for _, name := range []string{"c-web", "a-api", "b-mail"} {
		in := issuance.CertInput{Name: name, CommonName: name + ".example.test"}
		if _, err := f.store.CreateCertificate(context.Background(), f.org, in); err != nil {
			t.Fatal(err)
		}
	}
	one := 1
	res, err := f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org, Params: gen.ListCertificatesParams{Limit: &one}})
	if err != nil {
		t.Fatal(err)
	}
	page1 := res.(gen.ListCertificates200JSONResponse)
	if len(page1.Items) != 1 || page1.Items[0].Name != "a-api" || page1.NextCursor == nil {
		t.Fatalf("page1 = %+v", page1)
	}
	res, err = f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org,
		Params: gen.ListCertificatesParams{Limit: &one, Cursor: page1.NextCursor}})
	if err != nil {
		t.Fatal(err)
	}
	page2 := res.(gen.ListCertificates200JSONResponse)
	if len(page2.Items) != 1 || page2.Items[0].Name != "b-mail" {
		t.Fatalf("page2 = %+v", page2)
	}
	q := "mail"
	res, err = f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org, Params: gen.ListCertificatesParams{Q: &q}})
	if err != nil {
		t.Fatal(err)
	}
	filtered := res.(gen.ListCertificates200JSONResponse)
	if len(filtered.Items) != 1 || filtered.Items[0].Name != "b-mail" {
		t.Fatalf("q filter = %+v", filtered)
	}
}

// TestListCertificatesKeysetSurvivesInsert is the Review Focus for the
// keyset cursor fix: an offset cursor over an in-memory sort would either
// skip or repeat a row here, because inserting "a-api" between the two
// list calls shifts every row after it by one position. A keyset cursor
// resumes strictly after the specific (name, id) pair page 1 ended on, so
// the insert can only ever affect what page 1 itself would have returned
// (had it run after the insert), never what page 2 returns from an
// already-issued cursor: "a-api" sorts before that anchor, so it must not
// appear on page 2, "b-mail" must not repeat, and "c-web" must not be
// skipped.
func TestListCertificatesKeysetSurvivesInsert(t *testing.T) {
	f := newAPIFixture(t)
	for _, name := range []string{"b-mail", "c-web"} {
		in := issuance.CertInput{Name: name, CommonName: name + ".example.test"}
		if _, err := f.store.CreateCertificate(context.Background(), f.org, in); err != nil {
			t.Fatal(err)
		}
	}
	one := 1
	res, err := f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org, Params: gen.ListCertificatesParams{Limit: &one}})
	if err != nil {
		t.Fatal(err)
	}
	page1 := res.(gen.ListCertificates200JSONResponse)
	if len(page1.Items) != 1 || page1.Items[0].Name != "b-mail" || page1.NextCursor == nil {
		t.Fatalf("page1 = %+v", page1)
	}

	// Insert a row that sorts before the cursor's anchor, between the two
	// page fetches - exactly the case that breaks an offset cursor.
	in := issuance.CertInput{Name: "a-api", CommonName: "a-api.example.test"}
	if _, err := f.store.CreateCertificate(context.Background(), f.org, in); err != nil {
		t.Fatal(err)
	}

	res, err = f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org,
		Params: gen.ListCertificatesParams{Limit: &one, Cursor: page1.NextCursor}})
	if err != nil {
		t.Fatal(err)
	}
	page2 := res.(gen.ListCertificates200JSONResponse)
	if len(page2.Items) != 1 || page2.Items[0].Name != "c-web" {
		t.Fatalf("page2 skipped or duplicated a row after a concurrent insert: %+v", page2)
	}
}

// TestListCertificatesTamperedCursor is the Review Focus for cursor
// binding: a cursor decoded against different status/q/sort query
// parameters than the ones it was issued for must be rejected, not
// silently resume from the wrong place; so must a cursor string that isn't
// valid base64url/JSON at all.
func TestListCertificatesTamperedCursor(t *testing.T) {
	f := newAPIFixture(t)
	for _, name := range []string{"a-api", "b-mail"} {
		in := issuance.CertInput{Name: name, CommonName: name + ".example.test"}
		if _, err := f.store.CreateCertificate(context.Background(), f.org, in); err != nil {
			t.Fatal(err)
		}
	}
	one := 1
	res, err := f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org, Params: gen.ListCertificatesParams{Limit: &one}})
	if err != nil {
		t.Fatal(err)
	}
	cursor := res.(gen.ListCertificates200JSONResponse).NextCursor
	if cursor == nil {
		t.Fatal("want a next cursor")
	}

	// The same cursor replayed with a different q no longer matches what it
	// was issued for.
	q := "mail"
	_, err = f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org,
		Params: gen.ListCertificatesParams{Limit: &one, Cursor: cursor, Q: &q}})
	wantStatus(t, err, http.StatusUnprocessableEntity)

	// A cursor that isn't the opaque format at all.
	junk := "not-a-real-cursor"
	_, err = f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org,
		Params: gen.ListCertificatesParams{Limit: &one, Cursor: &junk}})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

// TestListCertificatesStatusFilterAndSort exercises the status filter and
// two SQL-level sorts (status, nextRenewAt) end to end; the existing list
// test only exercised the default name sort.
func TestListCertificatesStatusFilterAndSort(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	var failedID string
	for _, name := range []string{"a", "c"} {
		in := issuance.CertInput{Name: name, CommonName: name + ".example.test"}
		if _, err := f.store.CreateCertificate(ctx, f.org, in); err != nil {
			t.Fatal(err)
		}
	}
	in := issuance.CertInput{Name: "b", CommonName: "b.example.test"}
	failed, err := f.store.CreateCertificate(ctx, f.org, in)
	if err != nil {
		t.Fatal(err)
	}
	failedID = failed.ID.String()
	if err := f.store.MarkFailed(ctx, failed.ID, "failed", 1, "boom", time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	status := "pending"
	res, err := f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org, Params: gen.ListCertificatesParams{Status: (*gen.ListCertificatesParamsStatus)(&status)}})
	if err != nil {
		t.Fatal(err)
	}
	pending := res.(gen.ListCertificates200JSONResponse)
	if len(pending.Items) != 2 || pending.Items[0].Name != "a" || pending.Items[1].Name != "c" {
		t.Fatalf("status=pending = %+v", pending)
	}

	status = "failed"
	res, err = f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org, Params: gen.ListCertificatesParams{Status: (*gen.ListCertificatesParamsStatus)(&status)}})
	if err != nil {
		t.Fatal(err)
	}
	failedPage := res.(gen.ListCertificates200JSONResponse)
	if len(failedPage.Items) != 1 || failedPage.Items[0].Id.String() != failedID {
		t.Fatalf("status=failed = %+v", failedPage)
	}

	sortStatus := "status"
	res, err = f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org, Params: gen.ListCertificatesParams{Sort: &sortStatus}})
	if err != nil {
		t.Fatal(err)
	}
	byStatus := res.(gen.ListCertificates200JSONResponse)
	if len(byStatus.Items) != 3 || byStatus.Items[0].Status != "failed" || byStatus.Items[1].Status != "pending" || byStatus.Items[2].Status != "pending" {
		t.Fatalf("sort=status = %+v", byStatus)
	}

	sortNextRenewDesc := "-nextRenewAt"
	res, err = f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org, Params: gen.ListCertificatesParams{Sort: &sortNextRenewDesc}})
	if err != nil {
		t.Fatal(err)
	}
	byRenew := res.(gen.ListCertificates200JSONResponse)
	if len(byRenew.Items) != 3 || byRenew.Items[0].Name != "b" {
		t.Fatalf("sort=-nextRenewAt = %+v", byRenew)
	}
}

// TestCertificateManagedAndHasKey checks the Phase 4A contract fields
// mapped for real in Task 2: every certificate CreateCertificate makes is
// managed (the managed column defaults true), and ariWindow stays null
// until a poll has actually fetched one (TestCertificateARIWindowAPI,
// Task 12); a stored version reports hasKey true.
func TestCertificateManagedAndHasKey(t *testing.T) {
	f := newAPIFixture(t)
	c, v := f.issuedCert(t, "web")

	res, err := f.srv.GetCertificate(f.as("operator"), gen.GetCertificateRequestObject{OrgId: f.org, Id: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(gen.GetCertificate200JSONResponse)
	if !got.Managed {
		t.Errorf("managed = %v, want true", got.Managed)
	}
	if got.AriWindow != nil {
		t.Errorf("ariWindow = %+v, want nil", got.AriWindow)
	}

	vs, err := f.srv.ListCertificateVersions(f.as("operator"), gen.ListCertificateVersionsRequestObject{OrgId: f.org, Id: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	list := vs.(gen.ListCertificateVersions200JSONResponse)
	if len(list) != 1 || list[0].Id != v.ID || !list[0].HasKey {
		t.Fatalf("versions response = %+v", list)
	}

	// An unmanaged certificate (Task 13 sets this through upload/import;
	// direct SQL stands in until then) must round-trip managed=false, not a
	// hard-coded true.
	unmanaged, _ := f.issuedCert(t, "web-unmanaged")
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE certificates SET managed = false, next_renew_at = NULL WHERE id = $1`, unmanaged.ID); err != nil {
		t.Fatal(err)
	}
	res2, err := f.srv.GetCertificate(f.as("operator"), gen.GetCertificateRequestObject{OrgId: f.org, Id: unmanaged.ID})
	if err != nil {
		t.Fatal(err)
	}
	got2 := res2.(gen.GetCertificate200JSONResponse)
	if got2.Managed {
		t.Errorf("managed = %v, want false", got2.Managed)
	}
}

// ariAPISigner is a minimal signer.Signer standing in for the real ACME
// signer, so TestCertificateARIWindowAPI can drive a real ARIPollWorker
// without a live CA.
type ariAPISigner struct{ win *signer.Window }

func (ariAPISigner) Kind() string { return "fake" }
func (ariAPISigner) Issue(context.Context, signer.IssueRequest) (*signer.Issued, error) {
	return nil, errors.New("Issue must not be called")
}
func (ariAPISigner) Revoke(context.Context, *x509.Certificate, int) error { return nil }
func (s ariAPISigner) RenewalInfo(context.Context, *x509.Certificate) (*signer.Window, error) {
	return s.win, nil
}

// TestCertificateARIWindowAPI: ariWindow is populated (start, end,
// checkedAt) on the certificate response once ARIPollWorker has actually
// polled it, wiring together the SetARIWindow write (ari.go) and
// certRender's ariWindowOut (certificates.go).
func TestCertificateARIWindowAPI(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	ca, err := f.store.CreateCA(ctx, f.org, issuance.CAInput{Name: "ari-ca", Preset: "custom", DirectoryURL: "https://ca.test/dir", Resolvers: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	useAri := issuance.RenewPolicy{Mode: issuance.RenewPercent, Value: 33, UseARI: true}
	c, err := f.store.CreateCertificate(ctx, f.org, issuance.CertInput{
		Name: "ari-api", CommonName: "ari-api.example.test", Overrides: issuance.Defaults{RenewPolicy: &useAri},
	})
	if err != nil {
		t.Fatal(err)
	}
	leafDER, chainDER, pkcs8 := realCert(t, "ari-api.example.test", time.Now().UnixNano())
	iss := &signer.Issued{LeafDER: leafDER, ChainDER: chainDER, PrivateKeyPKCS8: pkcs8,
		NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour), Serial: "0c"}
	tx, err := f.store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.certs.Insert(ctx, tx, c.ID, iss, "ec256", certstore.InsertOpts{Source: "issued", CAID: &ca.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE certificates SET current_version_id = $2, status = 'active', next_renew_at = $3 WHERE id = $1`,
		c.ID, v.ID, time.Now().Add(90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Before any poll: ariWindow stays null.
	res, err := f.srv.GetCertificate(f.as("operator"), gen.GetCertificateRequestObject{OrgId: f.org, Id: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(gen.GetCertificate200JSONResponse); got.AriWindow != nil {
		t.Fatalf("ariWindow before any poll = %+v, want nil", got.AriWindow)
	}

	win := &signer.Window{Start: time.Now().Add(24 * time.Hour).Truncate(time.Microsecond), End: time.Now().Add(48 * time.Hour).Truncate(time.Microsecond)}
	aw := issuance.NewARIPollWorker(f.store, f.certs)
	aw.NewSigner = func(context.Context, issuance.CA) (signer.Signer, error) { return ariAPISigner{win: win}, nil }
	if err := aw.PollDue(ctx, 500); err != nil {
		t.Fatal(err)
	}

	res, err = f.srv.GetCertificate(f.as("operator"), gen.GetCertificateRequestObject{OrgId: f.org, Id: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	got := res.(gen.GetCertificate200JSONResponse)
	if got.AriWindow == nil {
		t.Fatal("ariWindow after poll = nil, want populated")
	}
	if !got.AriWindow.Start.Equal(win.Start) || !got.AriWindow.End.Equal(win.End) {
		t.Fatalf("ariWindow = %+v, want start=%v end=%v", got.AriWindow, win.Start, win.End)
	}
	if got.AriWindow.CheckedAt.IsZero() {
		t.Fatal("ariWindow.checkedAt is zero")
	}
}

// TestListAttemptsOmitsLogUnlessAsked: the list leaves the (up to 64 KB) log
// out by default, includeLog brings it back, and getIssuanceAttempt returns
// one attempt's log.
func TestListAttemptsOmitsLogUnlessAsked(t *testing.T) {
	f := newAPIFixture(t)
	ctx := f.as("viewer")
	c, _ := f.issuedCert(t, "web")
	id, err := f.store.CreateAttempt(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveAttemptProgress(ctx, nil, id, nil, "line one\n"); err != nil {
		t.Fatal(err)
	}
	list := func(include *bool) gen.IssuanceAttempt {
		res, err := f.srv.ListIssuanceAttempts(ctx, gen.ListIssuanceAttemptsRequestObject{OrgId: f.org, Id: c.ID,
			Params: gen.ListIssuanceAttemptsParams{IncludeLog: include}})
		if err != nil {
			t.Fatal(err)
		}
		out := res.(gen.ListIssuanceAttempts200JSONResponse)
		if len(out) != 1 {
			t.Fatalf("attempts = %+v", out)
		}
		return out[0]
	}
	if a := list(nil); a.Log != nil {
		t.Fatalf("default list carries a log: %q", *a.Log)
	}
	yes := true
	if a := list(&yes); a.Log == nil || *a.Log != "line one\n" {
		t.Fatalf("includeLog list log = %v", a.Log)
	}
	res, err := f.srv.GetIssuanceAttempt(ctx, gen.GetIssuanceAttemptRequestObject{OrgId: f.org, Id: c.ID, AttemptId: id})
	if err != nil {
		t.Fatal(err)
	}
	if a := gen.IssuanceAttempt(res.(gen.GetIssuanceAttempt200JSONResponse)); a.Log == nil || *a.Log != "line one\n" {
		t.Fatalf("get log = %v", a.Log)
	}
	_, err = f.srv.GetIssuanceAttempt(ctx, gen.GetIssuanceAttemptRequestObject{OrgId: f.org, Id: c.ID, AttemptId: uuid.New()})
	wantStatus(t, err, http.StatusNotFound)
}
