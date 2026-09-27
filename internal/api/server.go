// Package api wires the HTTP surface: the generated strict server, auth
// middleware, problem+json errors, the OpenAPI document, and health checks.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agenthub"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/config"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/meta"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/setup"
)

// Deps are the services handlers use.
type Deps struct {
	Config        config.Config
	Log           *slog.Logger
	Pool          *pgxpool.Pool
	Queries       *sqlcgen.Queries
	Settings      *settings.Store
	Sections      *settings.Registry
	Meta          *meta.Registry
	Sessions      *authn.Sessions
	Auditor       *audit.Auditor
	AuthSettings  *authn.SettingsSource // authentication section; nil falls back to RemoteAddr
	LoginLimiter  *authn.Limiter        // nil: authn.DefaultLoginPerMinute/DefaultLoginBurst
	EnrollLimiter *authn.Limiter        // per-IP limit on POST /agent/v1/enroll; nil: login defaults
	OIDC          *authn.OIDC           // single sign-on client (Task 6)
	Setup         *setup.Service
	Issuance      *issuance.Service // Store, certstore and the river job queue (Tasks 12-14)
	Certs         *certstore.Store  // certificate versions (Task 14)
	Box           crypto.Box        // seals a layout's export password (Phase 4A Task 5)

	Agents        *agents.Service        // clients, grants, sync (Phase 3)
	AgentSettings *agents.SettingsSource // agents settings section; PUT invalidates it
	Hub           *agenthub.Hub          // agent WebSockets (nil: /agent/v1/ws answers 503)
	AgentListener *agentca.Listener      // agent listener certificate (nil when not running)

	// DNSTestTimeout bounds POST .../dns-credentials/{id}/test; zero means
	// the 2-minute default (a test override, since lego's Present/CleanUp
	// take no context and can't be preempted, only raced against a timer).
	DNSTestTimeout time.Duration

	// AuditVerifyTTL caches GET /audit/verify's result; zero means 60 s.
	AuditVerifyTTL time.Duration
}

// Server implements gen.StrictServerInterface, one file per resource.
type Server struct {
	d Deps

	verifyMu  sync.Mutex
	verifyAt  time.Time
	verifyRes gen.AuditChainStatus
}

var _ gen.StrictServerInterface = (*Server)(nil)

// authorize returns the principal if it may perform action in orgID.
func authorize(ctx context.Context, action authz.Action, orgID *uuid.UUID) (authn.Principal, error) {
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return authn.Principal{}, errUnauthenticated
	}
	if !authz.Can(p, action, orgID) {
		return p, &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: fmt.Sprintf("missing permission %s", action)}
	}
	return p, nil
}

// queries returns Deps.Queries, or queries over Deps.Pool when a test
// fixture left it unset.
func (s *Server) queries() *sqlcgen.Queries {
	if s.d.Queries != nil {
		return s.d.Queries
	}
	return sqlcgen.New(s.d.Pool)
}
