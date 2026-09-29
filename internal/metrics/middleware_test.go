package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestHTTPMetricsUseRoutePattern covers the Shared contract's cardinality
// requirement: certforge_http_requests_total/certforge_http_request_duration_seconds
// are labelled with chi's route pattern (read after routing has run), never
// the raw path a concrete org id would otherwise put into the label set.
func TestHTTPMetricsUseRoutePattern(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware)
	r.Get("/api/v1/orgs/{orgId}/certificates", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/acme/certificates", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	const pattern = "/api/v1/orgs/{orgId}/certificates"
	if got := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(pattern, "GET", "200")); got != 1 {
		t.Fatalf("route-pattern label count = %v, want 1", got)
	}
	if got := testutil.ToFloat64(httpRequestsTotal.WithLabelValues("/api/v1/orgs/acme/certificates", "GET", "200")); got != 0 {
		t.Fatalf("raw path used as a label: count = %v, want 0", got)
	}
	h, ok := httpRequestDuration.WithLabelValues(pattern).(prometheus.Histogram)
	if !ok {
		t.Fatal("WithLabelValues did not return a prometheus.Histogram")
	}
	if n := testutil.CollectAndCount(h); n != 1 {
		t.Fatalf("duration observations for %q = %d, want 1", pattern, n)
	}
}

// TestHTTPMetricsUnmatchedRoute: a request chi never resolved a pattern for
// (the SPA fallback, served from NotFound) labels as "unmatched", not "".
func TestHTTPMetricsUnmatchedRoute(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware)
	// A router with no registered route at all never builds chi's internal
	// handler (mx.handler stays nil, and chi calls NotFoundHandler()
	// directly, skipping every middleware including this one) — a real
	// route keeps this test representative of the actual app router, which
	// always has plenty of matched routes beside its NotFound fallback.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })

	req := httptest.NewRequest(http.MethodGet, "/o/home/overview", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if got := testutil.ToFloat64(httpRequestsTotal.WithLabelValues("unmatched", "GET", "404")); got != 1 {
		t.Fatalf("unmatched count = %v, want 1", got)
	}
}
