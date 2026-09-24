package api

import (
	"log/slog"
	"mime"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
)

// NewRouter builds the handler for the main HTTP listener.
func NewRouter(d Deps) http.Handler {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	s := &Server{d: d}
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, securityHeaders)
	mountDocs(r)
	r.Route("/api/v1", func(v1 chi.Router) {
		v1.Use(withClientIP, requireJSON, authn.Middleware(authn.MiddlewareOptions{
			Sessions: d.Sessions, Queries: d.Queries, Public: isPublic, Fail: Write, Log: d.Log,
		}))
		v1.NotFound(func(w http.ResponseWriter, _ *http.Request) { Write(w, http.StatusNotFound, "Not found", "") })
		v1.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
			Write(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		})
		v1.Get("/openapi.json", serveSpec)
		strict := gen.NewStrictHandlerWithOptions(s, nil, gen.StrictHTTPServerOptions{
			RequestErrorHandlerFunc:  requestError,
			ResponseErrorHandlerFunc: s.responseError,
		})
		gen.HandlerWithOptions(strict, gen.ChiServerOptions{BaseRouter: v1, ErrorHandlerFunc: requestError})
	})
	return r
}

func isPublic(r *http.Request) bool {
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v1/openapi.json",
		"GET /api/v1/setup/status",
		"POST /api/v1/setup/complete",
		"POST /api/v1/auth/login":
		return true
	}
	return false
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func withClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		next.ServeHTTP(w, r.WithContext(audit.WithIP(r.Context(), ip)))
	})
}

// requireJSON rejects non-JSON bodies so cross-site HTML forms cannot reach
// the API (they cannot send application/json without a CORS preflight).
func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			if r.ContentLength != 0 {
				mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || mt != "application/json" {
					Write(w, http.StatusUnsupportedMediaType, "Unsupported media type", "Send request bodies as application/json.")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
