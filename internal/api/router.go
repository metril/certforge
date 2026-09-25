package api

import (
	"errors"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/webui"
)

// NewRouter builds the handler for the main HTTP listener.
func NewRouter(d Deps) http.Handler {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	// loginLimiterSettings drives Reconfigure from the authentication
	// section's loginRatePerMinute/loginBurst, but only for the limiter
	// built here: a caller-supplied LoginLimiter is used exactly as given.
	var loginLimiterSettings *authn.SettingsSource
	if d.LoginLimiter == nil {
		d.LoginLimiter = authn.NewLimiter(authn.DefaultLoginPerMinute, authn.DefaultLoginBurst)
		loginLimiterSettings = d.AuthSettings
	}
	s := &Server{d: d}
	r := chi.NewRouter()
	r.Use(recoverer(d.Log), securityHeaders)
	webHandler := webui.Handler()
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			Write(w, http.StatusNotFound, "Not found", "")
			return
		}
		// Any path chi has no route for is a client-side SPA route (or the
		// UI's own root); webHandler serves index.html for those.
		webHandler.ServeHTTP(w, r)
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			Write(w, http.StatusMethodNotAllowed, "Method not allowed", "")
			return
		}
		http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
	})
	mountDocs(r)
	r.Get("/healthz", s.healthz)
	r.Get("/readyz", s.readyz)
	r.Route("/api/v1", func(v1 chi.Router) {
		v1.Use(withClientIP(d.AuthSettings), limitLogins(d.LoginLimiter, loginLimiterSettings, d.Auditor, d.Log), requireJSON, authn.Middleware(authn.MiddlewareOptions{
			Sessions: d.Sessions, Queries: d.Queries, Public: isPublic, Fail: Write, Log: d.Log,
		}))
		v1.NotFound(func(w http.ResponseWriter, _ *http.Request) { Write(w, http.StatusNotFound, "Not found", "") })
		v1.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
			Write(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		})
		v1.Get("/openapi.json", serveSpec)
		strict := gen.NewStrictHandlerWithOptions(s, []gen.StrictMiddlewareFunc{withHTTP}, gen.StrictHTTPServerOptions{
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
		"POST /api/v1/auth/login",
		"GET /api/v1/auth/methods":
		return true
	}
	return false
}

// limitLogins applies the per-client login rate limit to the password login
// and the OIDC callback. When src is non-nil, l is reconfigured from the
// authentication section's loginRatePerMinute/loginBurst before every check.
// A rate-limited attempt is audited as session.login_failed, same as a bad
// password, so the audit log shows every rejected login attempt.
func limitLogins(l *authn.Limiter, src *authn.SettingsSource, aud *audit.Auditor, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var method string
			switch r.Method + " " + r.URL.Path {
			case "POST /api/v1/auth/login":
				method = "local"
			case "GET /api/v1/auth/oidc/callback":
				method = "oidc"
			default:
				next.ServeHTTP(w, r)
				return
			}
			if src != nil {
				if st, err := src.Get(r.Context()); err == nil {
					l.Reconfigure(st.LoginRatePerMinute, st.LoginBurst)
				}
			}
			if ok, wait := l.Allow(authn.LimitKey(audit.IPFrom(r.Context()))); !ok {
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
				if aud != nil {
					if err := aud.Record(r.Context(), audit.Event{
						Action: "session.login_failed", ResourceType: "user", ActorType: "anonymous",
						Details: map[string]any{"reason": "rate_limited", "method": method},
					}); err != nil && log != nil {
						log.Error("audit record failed", "action", "session.login_failed", "err", err)
					}
				}
				Write(w, http.StatusTooManyRequests, "Too many login attempts", "Wait before trying again.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// contentSecurityPolicy is served on every response. script-src 'self' holds
// because the UI's only scripts are same-origin files (theme pre-paint runs
// from /theme-init.js, not an inline script) and the vendored Swagger UI at
// /api/docs loads only its own same-origin bundle and init.js.
// style-src allows 'unsafe-inline' for Radix's inline style attributes and
// Swagger UI's injected <style> tags.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// withClientIP records the client address for audit events, honouring
// X-Forwarded-For only from the authentication section's trusted proxies.
func withClientIP(src *authn.SettingsSource) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := authn.RemoteIP(r)
			if src != nil {
				if st, err := src.Get(r.Context()); err == nil {
					ip = st.ClientIP(r)
				}
			}
			next.ServeHTTP(w, r.WithContext(audit.WithIP(r.Context(), ip)))
		})
	}
}

// maxRequestBody caps request bodies (including on public, unauthenticated
// routes such as login and setup) so a client cannot exhaust server memory
// or CPU with an oversized JSON payload.
const maxRequestBody = 1 << 20 // 1 MiB

// requireJSON rejects non-JSON bodies so cross-site HTML forms cannot reach
// the API (they cannot send application/json without a CORS preflight), and
// caps the body size read by any later handler.
func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
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
