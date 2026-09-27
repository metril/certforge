//go:build integration

package api

import (
	"encoding/pem"
	"testing"

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
