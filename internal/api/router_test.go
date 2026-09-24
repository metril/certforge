package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

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

func TestSecurityHeaders(t *testing.T) {
	rec := serve(t, http.MethodGet, "/api/v1/orgs", "", "")
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("headers %v", rec.Header())
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
