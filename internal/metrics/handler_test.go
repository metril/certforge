package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMetricsDisabled404 covers the Shared contract: GET /metrics is 404
// while the "prometheus" section is disabled. handler.load is stubbed
// directly (no *settings.Store/database) — the same testability convention
// authn.SettingsSource.load documents.
func TestMetricsDisabled404(t *testing.T) {
	h := &handler{load: func(context.Context) (Settings, error) { return Settings{Enabled: false}, nil }}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", rec.Body.String())
	}
}

// TestMetricsLoadErrorAlso404: a settings-load failure (registry not wired,
// or a database error) never leaks as a 500 or panics; it degrades to the
// same 404 a disabled section gives.
func TestMetricsLoadErrorAlso404(t *testing.T) {
	h := &handler{load: func(context.Context) (Settings, error) { return Settings{}, errors.New("boom") }}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rec.Code)
	}
}

// TestMetricsUnauthorizedEmptyBody covers the Shared contract: a missing or
// wrong Authorization: Bearer gives 401 with an empty body and
// WWW-Authenticate: Bearer, compared in constant time.
func TestMetricsUnauthorizedEmptyBody(t *testing.T) {
	h := &handler{load: func(context.Context) (Settings, error) {
		return Settings{Enabled: true, BearerToken: "correct-horse-battery-staple"}, nil
	}}

	for _, auth := range []string{"", "Bearer wrong-token", "Bearer", "Basic correct-horse-battery-staple"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("auth %q: code = %d, want 401", auth, rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("auth %q: body = %q, want empty", auth, rec.Body.String())
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("auth %q: WWW-Authenticate = %q, want %q", auth, got, "Bearer")
		}
	}
}

// TestMetricsAuthorized: the right bearer token serves the Prometheus
// exposition format from Registry.
func TestMetricsAuthorized(t *testing.T) {
	h := &handler{load: func(context.Context) (Settings, error) {
		return Settings{Enabled: true, BearerToken: "correct-horse-battery-staple"}, nil
	}}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer correct-horse-battery-staple")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") == "" {
		t.Fatal("expected a Content-Type from promhttp")
	}
	if rec.Body.Len() == 0 {
		t.Fatal("expected a non-empty scrape body")
	}
}
