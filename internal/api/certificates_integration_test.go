//go:build integration

package api

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

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
