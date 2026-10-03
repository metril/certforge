package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestSPAFallback(t *testing.T) {
	h := newHandler(fstest.MapFS{
		"index.html":    {Data: []byte("<html>app</html>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	})
	for _, p := range []string{"/", "/index.html", "/o/home/certificates/123", "/settings/general"} {
		rec := get(h, p)
		if rec.Code != 200 || rec.Body.String() != "<html>app</html>" || rec.Header().Get("Cache-Control") != "no-cache" {
			t.Fatalf("%s: %d %q %q", p, rec.Code, rec.Body, rec.Header().Get("Cache-Control"))
		}
	}
	rec := get(h, "/assets/app.js")
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset %d %v", rec.Code, rec.Header())
	}
	if rec := get(h, "/api/v2/nope"); rec.Code != 404 {
		t.Fatalf("api path %d", rec.Code)
	}
}

func TestMissingStaticIs404(t *testing.T) {
	h := newHandler(fstest.MapFS{"index.html": {Data: []byte("<html>app</html>")}})
	for _, p := range []string{"/assets/gone.js", "/assets/sub/gone", "/favicon.ico", "/o/home/gone.map"} {
		if rec := get(h, p); rec.Code != 404 {
			t.Fatalf("%s: %d", p, rec.Code)
		}
	}
}

func TestGzip(t *testing.T) {
	h := newHandler(fstest.MapFS{"index.html": {Data: []byte(strings.Repeat("<html>app</html>", 200))}})
	req := httptest.NewRequest(http.MethodGet, "/o/home/overview", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("headers %v", rec.Header())
	}
}

func TestPlaceholder(t *testing.T) {
	rec := get(Handler(), "/o/home/overview")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "CertForge") {
		t.Fatalf("placeholder %d %s", rec.Code, rec.Body)
	}
}
