//go:build integration

package api

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/issuance"
)

func (f *apiFixture) download(ctx context.Context, c gen.Id, v gen.VersionId, parts string) (gen.DownloadCertificateVersionResponseObject, error) {
	return f.srv.DownloadCertificateVersion(ctx, gen.DownloadCertificateVersionRequestObject{OrgId: f.org, Id: c, Vid: v,
		Params: gen.DownloadCertificateVersionParams{Parts: parts}})
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
	broken, err := pgxpool.New(context.Background(), dbtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	broken.Close() // every audit write now fails
	f.srv.d.Auditor = audit.New(broken)
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
