package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// Middleware records certforge_http_requests_total{route,method,status} and
// certforge_http_request_duration_seconds{route} for every request (Shared
// contract). route is chi's own route pattern, read from
// chi.RouteContext(r.Context()).RoutePattern() after next.ServeHTTP runs —
// chi only resolves the pattern once routing has actually happened — never
// the raw path (an id in the path would otherwise blow up the series'
// cardinality), and "unmatched" when chi never resolved one (a request
// outside chi's routed tree, such as the SPA fallback path). Mounted with
// r.Use right after recoverer, so every response — including a panic's own
// 500 — is counted.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		pattern := "unmatched"
		if rc := chi.RouteContext(r.Context()); rc != nil {
			if p := rc.RoutePattern(); p != "" {
				pattern = p
			}
		}
		httpRequestsTotal.WithLabelValues(pattern, r.Method, strconv.Itoa(sw.status)).Inc()
		httpRequestDuration.WithLabelValues(pattern).Observe(time.Since(start).Seconds())
	})
}

// statusWriter captures the status code a handler wrote (defaulting to 200,
// http.ResponseWriter's own implicit status when Write runs without an
// explicit WriteHeader first) so Middleware can label its counter with it.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush passes through to the underlying ResponseWriter when it supports
// streaming (a backup download, Phase 6A Task 12), so wrapping it here
// never buffers a response that expects to be flushed incrementally.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
