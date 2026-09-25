package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// agentAPI serves /agent/v1/* on the agent listener. Handlers are plain
// net/http: the surface is small and not part of the public OpenAPI spec.
type agentAPI struct{ d Deps }

// NewAgentRouter builds the handler for the agent listener (CF_LISTEN_AGENT):
// mutual TLS, /agent/v1/* only, no browser content, so no CSP or HSTS.
func NewAgentRouter(d Deps) http.Handler {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.EnrollLimiter == nil {
		d.EnrollLimiter = authn.NewLimiter(authn.DefaultLoginPerMinute, authn.DefaultLoginBurst)
	}
	a := &agentAPI{d: d}
	r := chi.NewRouter()
	r.Use(recoverer(d.Log), requireJSON)
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) { Write(w, http.StatusNotFound, "Not found", "") })
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		Write(w, http.StatusMethodNotAllowed, "Method not allowed", "")
	})
	r.Route("/agent/v1", func(v1 chi.Router) {
		v1.With(a.limitEnroll).Post("/enroll", a.enroll)
		v1.Group(func(g chi.Router) {
			g.Use(a.requireAgent)
			g.Post("/renew", a.renew)
			g.Get("/assignments", a.assignments)
			g.Get("/grants/{id}/bundle", a.bundle)
			g.Post("/report", a.report)
			g.Post("/heartbeat", a.heartbeat)
			g.Get("/ws", a.ws)
		})
	})
	return r
}

type agentClientKey struct{}

// agentClient is the client authenticated by requireAgent.
func agentClient(ctx context.Context) sqlcgen.Client {
	c, _ := ctx.Value(agentClientKey{}).(sqlcgen.Client)
	return c
}

func (a *agentAPI) limitEnroll(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := authn.RemoteIP(r)
		if ok, wait := a.d.EnrollLimiter.Allow(authn.LimitKey(ip)); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			Write(w, http.StatusTooManyRequests, "Too many enrolment attempts", "Wait before trying again.")
			return
		}
		next.ServeHTTP(w, r.WithContext(audit.WithIP(r.Context(), ip)))
	})
}

// requireAgent admits only a verified agent certificate whose client is
// active and whose serial is the newest issued to it.
func (a *agentAPI) requireAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			Write(w, http.StatusUnauthorized, "Unauthorized", "A client certificate from the agent CA is required.")
			return
		}
		c, err := a.d.Agents.Authenticate(r.Context(), r.TLS.PeerCertificates[0])
		if err != nil {
			writeAgentErr(w, a.d.Log, err)
			return
		}
		ctx := authn.WithPrincipal(r.Context(), agents.AgentPrincipal(c))
		ctx = audit.WithIP(ctx, authn.RemoteIP(r))
		ctx = context.WithValue(ctx, agentClientKey{}, c)
		next.ServeHTTP(w, r.WithContext(ctx))
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
