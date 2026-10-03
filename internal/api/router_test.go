package api

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/meta"
)

func serve(t *testing.T, method, path, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewRouter(Deps{Meta: meta.NewRegistry()})
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestProtectedRouteNeedsAuth(t *testing.T) {
	for _, p := range []string{"/api/v1/orgs", "/api/v1/meta/schemas", "/api/v1/nope"} {
		rec := serve(t, http.MethodGet, p, "", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: code %d", p, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Fatalf("%s: content type %q", p, ct)
		}
		var prob map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil || prob["status"] != float64(401) {
			t.Fatalf("%s: body %s", p, rec.Body)
		}
	}
}

func TestOpenAPIServed(t *testing.T) {
	rec := serve(t, http.MethodGet, "/api/v1/openapi.json", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	var doc struct {
		OpenAPI string         `json:"openapi"`
		Paths   map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.0.3" || doc.Paths["/orgs"] == nil {
		t.Fatalf("doc %+v", doc)
	}
}

func TestDocsServed(t *testing.T) {
	if rec := serve(t, http.MethodGet, "/api/docs", "", ""); rec.Code != http.StatusMovedPermanently {
		t.Fatalf("redirect code %d", rec.Code)
	}
	rec := serve(t, http.MethodGet, "/api/docs/", "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "swagger-ui-bundle.js") {
		t.Fatalf("docs %d", rec.Code)
	}
}

func TestRequireJSON(t *testing.T) {
	rec := serve(t, http.MethodPost, "/api/v1/auth/login", "text/plain", `{"password":"x"}`)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestBodyTooLarge(t *testing.T) {
	big := `{"password":"` + strings.Repeat("a", 2<<20) + `"}`
	rec := serve(t, http.MethodPost, "/api/v1/auth/login", "application/json", big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code %d body %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
	var prob map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil || prob["status"] != float64(413) {
		t.Fatalf("body %s", rec.Body)
	}
}

// wantCSP is a literal, independent copy of the expected policy (not a
// reference to router.go's contentSecurityPolicy constant), so a change
// that weakens the real policy fails this test instead of trivially
// matching itself.
const wantCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"

func TestSecurityHeaders(t *testing.T) {
	rec := serve(t, http.MethodGet, "/api/v1/orgs", "", "")
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("headers %v", rec.Header())
	}
	if rec.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("referrer-policy %v", rec.Header())
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != wantCSP {
		t.Fatalf("csp %q", got)
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatalf("HSTS should not be set over plain HTTP: %v", rec.Header())
	}
}

func TestSecurityHeadersHSTS(t *testing.T) {
	h := NewRouter(Deps{Meta: meta.NewRegistry()})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
		t.Fatalf("HSTS over TLS: %q", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/orgs", nil)
	req2.Header.Set("X-Forwarded-Proto", "https")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if got := rec2.Header().Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
		t.Fatalf("HSTS behind X-Forwarded-Proto=https: %q", got)
	}
}

func TestSecurityHeadersOnDocsAndSPA(t *testing.T) {
	for _, p := range []string{"/api/docs/", "/o/home/overview"} {
		rec := serve(t, http.MethodGet, p, "", "")
		if got := rec.Header().Get("Content-Security-Policy"); got != wantCSP {
			t.Fatalf("%s: csp %q", p, got)
		}
	}
}

func TestUnknownAPIPathIsProblem(t *testing.T) {
	rec := serve(t, http.MethodGet, "/api/foo", "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
	var prob map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil || prob["status"] != float64(404) {
		t.Fatalf("body %s", rec.Body)
	}
}

func TestRecovererWritesProblem(t *testing.T) {
	r := chi.NewRouter()
	r.Use(recoverer(slog.New(slog.NewTextHandler(io.Discard, nil))))
	r.Get("/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
	var prob map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil || prob["status"] != float64(500) {
		t.Fatalf("body %s", rec.Body)
	}
}

func TestWriteProblem(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, http.StatusConflict, "Conflict", "already done")
	var p map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if rec.Code != 409 || p["type"] != "about:blank" || p["title"] != "Conflict" || p["detail"] != "already done" {
		t.Fatalf("problem %d %v", rec.Code, p)
	}
}

func TestHealthz(t *testing.T) {
	rec := serve(t, http.MethodGet, "/healthz", "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("healthz %d %s", rec.Code, rec.Body)
	}
}

func TestSPAMounted(t *testing.T) {
	rec := serve(t, http.MethodGet, "/o/home/overview", "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "CertForge") {
		t.Fatalf("spa %d", rec.Code)
	}
}

// TestWellKnownHandler: GET /.well-known/acme-challenge/{token} is public
// (no session, not under /api/v1), returns the stored key authorization as
// text/plain for a known token, 404 for an unknown one or a token
// containing "." or "/" (the wildcard route also catches extra segments),
// and 405 for a non-GET method.
func TestWellKnownHandler(t *testing.T) {
	tokens := challenge.NewHTTPTokens(time.Minute)
	tokens.Put("tok123", "keyauth-value")
	h := NewRouter(Deps{Meta: meta.NewRegistry(), HTTPTokens: tokens})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/tok123", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "keyauth-value" {
		t.Fatalf("known token: %d %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type %q", ct)
	}

	for _, p := range []string{
		"/.well-known/acme-challenge/nope",
		"/.well-known/acme-challenge/a.b",
		"/.well-known/acme-challenge/a/b",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: code %d", p, rec.Code)
		}
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/.well-known/acme-challenge/tok123", nil))
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post code %d", rec2.Code)
	}
}

// TestWellKnownHandlerNoTokenStore: with no HTTPTokens configured (the
// default zero Deps), the route still answers 404 instead of falling
// through to the SPA (200) or panicking on a nil store.
func TestWellKnownHandlerNoTokenStore(t *testing.T) {
	rec := serve(t, http.MethodGet, "/.well-known/acme-challenge/tok123", "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code %d", rec.Code)
	}
}
