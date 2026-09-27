//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/metril/certforge/internal/api/gen"
)

// pemCert PEM-encodes a leaf DER for an upload request body.
func pemCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestUploadCertificateAPI is the Task 13 brief's core coverage: uploading
// a keyless PEM leaf creates an unmanaged certificate (managed false,
// nextRenewAt null), its current version reports source uploaded and
// hasKey false, and the write is audited as certificate.upload.
func TestUploadCertificateAPI(t *testing.T) {
	f := newAPIFixture(t)
	op := f.as("operator")
	leafDER, _, _ := realCert(t, "up.example.test", 501)
	body := pemCert(leafDER)

	res, err := f.srv.UploadCertificate(op, gen.UploadCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateUpload{Name: "web-upload", CertificatePem: &body}})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := res.(gen.UploadCertificate201JSONResponse)
	if !ok {
		t.Fatalf("response type = %T", res)
	}
	if c.Managed {
		t.Fatal("uploaded certificate is managed")
	}
	if c.NextRenewAt != nil {
		t.Fatalf("nextRenewAt = %v, want nil", c.NextRenewAt)
	}
	if c.CurrentVersion == nil {
		t.Fatal("no current version")
	}
	if string(c.CurrentVersion.Source) != "uploaded" {
		t.Fatalf("source = %s", c.CurrentVersion.Source)
	}
	if c.CurrentVersion.HasKey {
		t.Fatal("keyless upload reports hasKey true")
	}
	if c.CommonName != "up.example.test" {
		t.Fatalf("commonName = %q, want the leaf's own DNS name", c.CommonName)
	}
	if n := f.auditCount(t, "certificate.upload"); n != 1 {
		t.Fatalf("certificate.upload audit rows = %d", n)
	}
}

// TestUnmanagedRenewUpdate409 covers renewCertificate and updateCertificate
// both refusing an unmanaged (uploaded) certificate with 409 "managed
// externally".
func TestUnmanagedRenewUpdate409(t *testing.T) {
	f := newAPIFixture(t)
	op := f.as("operator")
	leafDER, _, _ := realCert(t, "unmanaged.example.test", 502)
	body := pemCert(leafDER)
	res, err := f.srv.UploadCertificate(op, gen.UploadCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateUpload{Name: "unmanaged-1", CertificatePem: &body}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.UploadCertificate201JSONResponse).Id

	_, err = f.srv.RenewCertificate(op, gen.RenewCertificateRequestObject{OrgId: f.org, Id: id})
	wantStatus(t, err, 409)

	_, err = f.srv.UpdateCertificate(op, gen.UpdateCertificateRequestObject{OrgId: f.org, Id: id,
		Body: &gen.CertificateInput{Name: "unmanaged-1", CommonName: "changed.example.test"}})
	wantStatus(t, err, 409)
}

// TestUploadVersionManaged409 covers uploadCertificateVersion refusing a
// still-managed certificate (the endpoint only ever adds a version to an
// unmanaged one).
func TestUploadVersionManaged409(t *testing.T) {
	f := newAPIFixture(t)
	op := f.as("operator")
	c, _ := f.issuedCert(t, "managed-1")
	leafDER, _, _ := realCert(t, "managed-1.example.test", 503)
	body := pemCert(leafDER)

	_, err := f.srv.UploadCertificateVersion(op, gen.UploadCertificateVersionRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.CertificateVersionUpload{CertificatePem: &body}})
	wantStatus(t, err, 409)
}

// TestUploadVersionAudited covers uploadCertificateVersion's own audit
// action, certificate.version_uploaded — distinct from certificate.upload,
// which only certificate creation records.
func TestUploadVersionAudited(t *testing.T) {
	f := newAPIFixture(t)
	op := f.as("operator")
	leafDER, _, _ := realCert(t, "audited.example.test", 601)
	body := pemCert(leafDER)
	res, err := f.srv.UploadCertificate(op, gen.UploadCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateUpload{Name: "audited", CertificatePem: &body}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.UploadCertificate201JSONResponse).Id

	leaf2DER, _, _ := realCert(t, "audited.example.test", 602)
	body2 := pemCert(leaf2DER)
	if _, err := f.srv.UploadCertificateVersion(op, gen.UploadCertificateVersionRequestObject{OrgId: f.org, Id: id,
		Body: &gen.CertificateVersionUpload{CertificatePem: &body2}}); err != nil {
		t.Fatal(err)
	}
	if n := f.auditCount(t, "certificate.version_uploaded"); n != 1 {
		t.Fatalf("certificate.version_uploaded audit rows = %d", n)
	}
}

// TestUploadExpiredStatus covers status active vs expired, computed from
// the leaf's own validity: a leaf already past its NotAfter uploads as
// status expired, not active.
func TestUploadExpiredStatus(t *testing.T) {
	f := newAPIFixture(t)
	op := f.as("operator")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-48 * time.Hour)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(701), Subject: pkix.Name{CommonName: "expired.example.test"},
		NotBefore: past.Add(-24 * time.Hour), NotAfter: past, DNSNames: []string{"expired.example.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	body := pemCert(der)

	res, err := f.srv.UploadCertificate(op, gen.UploadCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateUpload{Name: "expired-upload", CertificatePem: &body}})
	if err != nil {
		t.Fatal(err)
	}
	c := res.(gen.UploadCertificate201JSONResponse)
	if string(c.Status) != "expired" {
		t.Fatalf("status = %s, want expired", c.Status)
	}
}

// TestUploadKeySealed covers a keyed upload storing the key
// envelope-sealed (crypto.Box), not in the clear: the raw
// certificate_versions.private_key column never equals the plaintext
// PKCS#8 bytes that were uploaded.
func TestUploadKeySealed(t *testing.T) {
	f := newAPIFixture(t)
	op := f.as("operator")
	leafDER, _, pkcs8 := realCert(t, "sealed.example.test", 801)
	certBody := pemCert(leafDER)
	keyBody := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))

	res, err := f.srv.UploadCertificate(op, gen.UploadCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateUpload{Name: "sealed", CertificatePem: &certBody, PrivateKeyPem: &keyBody}})
	if err != nil {
		t.Fatal(err)
	}
	c := res.(gen.UploadCertificate201JSONResponse)
	if !c.CurrentVersion.HasKey {
		t.Fatal("keyed upload reports hasKey false")
	}

	var raw []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT private_key FROM certificate_versions WHERE id = $1`, c.CurrentVersion.Id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("no private_key stored")
	}
	if bytes.Equal(raw, pkcs8) {
		t.Fatal("private_key stored in the clear (matches the plaintext PKCS#8 upload)")
	}
}
