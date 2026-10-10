package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// agentAPI serves /agent/v1/* on the agent listener and, behind any
// TLS-terminating proxy, on the HTTP listener. Handlers are plain net/http:
// the surface is small and not part of the public OpenAPI spec.
type agentAPI struct {
	d        Deps
	httpPort bool // mounted on the HTTP router: the base URL host is also a valid @authority
	nonces   NonceStore
	sessions agentSessions
	sessLim  *authn.Limiter
	hellos   enrollHellos
	// refreshing is set while a late responder renewal runs.
	refreshing atomic.Bool
	now        func() time.Time // nil: time.Now
}

func newAgentAPI(d Deps, httpPort bool) *agentAPI {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.EnrollLimiter == nil {
		d.EnrollLimiter = authn.NewLimiter(authn.DefaultLoginPerMinute, authn.DefaultLoginBurst)
	}
	a := &agentAPI{d: d, httpPort: httpPort, nonces: d.AgentNonces, sessLim: authn.NewLimiter(600, 120)}
	if a.nonces == nil {
		a.nonces = newMemNonces()
	}
	return a
}

// NewAgentRouter builds the handler for the agent listener (CF_LISTEN_AGENT):
// /agent/v1/* only, no browser content, so no CSP or HSTS. It speaks the same
// application-layer protocol as the routes NewRouter mounts on the HTTP port.
func NewAgentRouter(d Deps) http.Handler {
	a := newAgentAPI(d, false)
	r := chi.NewRouter()
	r.Use(recoverer(a.d.Log))
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) { Write(w, http.StatusNotFound, "Not found", "") })
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		Write(w, http.StatusMethodNotAllowed, "Method not allowed", "")
	})
	r.Route("/agent/v1", a.routes)
	return r
}

// routes registers the agent protocol. /enroll* is the token-proof exchange,
// /session and /ws are signed handshakes, and every other route needs a signed
// request inside a session. A client certificate never authenticates anything.
func (a *agentAPI) routes(v1 chi.Router) {
	v1.Use(withClientIP(a.d.AuthSettings))
	v1.NotFound(func(w http.ResponseWriter, _ *http.Request) { Write(w, http.StatusNotFound, "Not found", "") })
	v1.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		Write(w, http.StatusMethodNotAllowed, "Method not allowed", "")
	})
	v1.With(a.limitEnroll).Get("/enroll/hello", a.enrollHello)
	v1.With(a.limitEnroll).Post("/enroll", a.enroll)
	v1.With(a.limitSession).Post("/enroll/{id}", a.enrollPoll)
	v1.With(a.limitSession).Post("/session", a.session)
	v1.With(a.limitSession).Get("/ws", a.ws)
	v1.Group(func(g chi.Router) {
		g.Use(a.limitSession, a.secure)
		g.Post("/renew", a.renew)
		g.Get("/assignments", a.assignments)
		g.Get("/grants/{id}/bundle", a.bundle)
		g.Post("/report", a.report)
		g.Post("/heartbeat", a.heartbeat)
	})
}

type agentClientKey struct{}

// agentClient is the client authenticated by the secure middleware.
func agentClient(ctx context.Context) sqlcgen.Client {
	c, _ := ctx.Value(agentClientKey{}).(sqlcgen.Client)
	return c
}

func (a *agentAPI) limitEnroll(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := audit.IPFrom(r.Context())
		if ok, wait := a.d.EnrollLimiter.Allow(authn.LimitKey(ip)); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			Write(w, http.StatusTooManyRequests, "Too many enrolment attempts", "Wait before trying again.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// limitSession rate-limits handshakes per client address (the real one, via
// the trusted proxies setting), before any signature work.
func (a *agentAPI) limitSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := a.sessLim.Allow(authn.LimitKey(audit.IPFrom(r.Context()))); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			Write(w, http.StatusTooManyRequests, "Too many requests", "Wait before opening another session.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			Write(w, http.StatusRequestEntityTooLarge, "Payload too large", "")
		} else {
			Write(w, http.StatusBadRequest, "Bad request", "The body is not valid JSON for this endpoint.")
		}
		return false
	}
	return true
}

func writeAgentErr(w http.ResponseWriter, log *slog.Logger, err error) {
	var he *HTTPError
	if errors.As(mapAgentErr(err), &he) {
		Write(w, he.Status, he.Title, he.Detail)
		return
	}
	log.Error("agent request failed", "err", err)
	Write(w, http.StatusInternalServerError, "Internal server error", "")
}
