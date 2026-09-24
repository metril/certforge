package api

import (
	"errors"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/go-chi/chi/v5"

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
	r.Use(recoverer(d.Log), securityHeaders)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			Write(w, http.StatusNotFound, "Not found", "")
			return
		}
		// Non-API paths keep the default 404 until Task 12 adds the SPA fallback.
		http.NotFound(w, r)
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			Write(w, http.StatusMethodNotAllowed, "Method not allowed", "")
			return
		}
		http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
	})
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

// recoverer replaces chi's middleware.Recoverer, which on panic writes a bare
// 500 with no body. It logs the panic and stack, then writes a problem+json
// 500 so every error response, including panics, matches the API contract.
func recoverer(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rvr := recover(); rvr != nil {
					if err, ok := rvr.(error); ok && errors.Is(err, http.ErrAbortHandler) {
						// Client disconnected; the runtime handles the connection
						// itself and expects the panic to propagate.
						panic(rvr)
					}
					log.Error("panic recovered", "method", r.Method, "path", r.URL.Path,
						"panic", rvr, "stack", string(debug.Stack()))
					Write(w, http.StatusInternalServerError, "Internal server error", "")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
