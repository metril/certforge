//go:build integration

package api_test

import (
	"archive/zip"
	"bytes"
	"mime/multipart"
	"net/http"
	"testing"
)

// TestImportRequiresMultipart covers router.go's requireJSON refusing
// importCertificates a JSON body (415): unlike every other write route,
// this one requires multipart/form-data instead.
func TestImportRequiresMultipart(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	resp, body := e.doRaw(http.MethodPost, "/api/v1/orgs/"+org.String()+"/certificates/import", "application/json", `{}`, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
}

// TestImportTooLarge covers importCertificates' own 32 MiB MaxBytesReader
// (router.go's requireJSON, its one exception to the global 1 MiB cap).
// Unlike a JSON body (where the strict server's own decode hits the limit
// before the handler runs), a multipart body's parts are read lazily: the
// strict server's r.MultipartReader() only parses headers, so this
// specifically exercises the handler's own read of the "archive" part
// (certificate_import.go's parseImportMultipart, via importer.
// ExtractArchive) hitting the MaxBytesReader mid-stream.
func TestImportTooLarge(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()

	// A real (uncompressed, so its size cannot shrink below the request
	// cap the way a highly compressible payload would) zip entry, well
	// over 32 MiB: this must be rejected for its size, not for looking
	// like garbage, so the archive's magic bytes need to be genuine.
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	zf, err := zw.CreateHeader(&zip.FileHeader{Name: "big.bin", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zf.Write(bytes.Repeat([]byte{'a'}, 33<<20)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("archive", "big.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(zbuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	resp, body := e.doRaw(http.MethodPost, "/api/v1/orgs/"+org.String()+"/certificates/import", w.FormDataContentType(), buf.String(), csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
}

// TestImportRequiresCSRF covers a fix-round-1 finding: requireJSON's
// import exception replaces the JSON-only Content-Type guard for this one
// route, but must not bypass session/CSRF enforcement (authn.Middleware,
// which runs after requireJSON) — a session request with a well-formed
// multipart body but no X-CSRF-Token still gets 403, same as every other
// write route.
func TestImportRequiresCSRF(t *testing.T) {
	e := newTestEnv(t)
	_, org := e.seedAdminSession()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("caId", "00000000-0000-0000-0000-000000000000"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	resp, body := e.doRaw(http.MethodPost, "/api/v1/orgs/"+org.String()+"/certificates/import", w.FormDataContentType(), buf.String(), "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
}
