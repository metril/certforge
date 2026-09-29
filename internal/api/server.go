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
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/config"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/deploy"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/kek"
	"github.com/metril/certforge/internal/meta"
	"github.com/metril/certforge/internal/monitor"
	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/setup"
	"github.com/metril/certforge/internal/vault"
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
	// HTTPTokens backs the public GET /.well-known/acme-challenge/{token}
	// route (Phase 4A Task 6); nil answers 404 for every token. Shared with
	// issuance.IssueWorker.HTTPTokens; see cmd/certforge/serve.go.
	HTTPTokens *challenge.HTTPTokens

	Agents        *agents.Service        // clients, grants, sync (Phase 3)
	AgentSettings *agents.SettingsSource // agents settings section; PUT invalidates it
	Hub           *agenthub.Hub          // agent WebSockets (nil: /agent/v1/ws answers 503)
	AgentListener *agentca.Listener      // agent listener certificate (nil when not running)

	// Keys reports the active KEK's status and starts its rewrap job
	// (Task 5: GET/POST /keys/*).
	Keys *kek.Service

	// Vault builds a live Vault client from the "vault" settings section,
	// for testVaultSettings and the vaultpki CA/signer (Task 8). nil
	// answers testVaultSettings with a connection failure result and every
	// vaultpki CA operation with a "not configured" 422.
	Vault *vault.Provider

	// KEKHealth reports the active KEK's own Vault reachability (its
	// sys/health) and is set only when the KEK is Transit (cmd/certforge's
	// buildKEK); nil means the KEK is static and has nothing to probe.
	// Backs /readyz's "vault" check (Task 13): a KEKHealth error makes the
	// server not ready, unlike a failure from Vault alone (below).
	KEKHealth func(ctx context.Context) error

	// Deploy holds server-run deploy target types (vault-kv, Task 10). A
	// nil registry (or a type it does not hold) makes CreateDeployTarget/
	// UpdateDeployTarget reject the type with 422, same as an unregistered
	// type today.
	Deploy *deploy.Registry

	// Dispatcher enqueues certforge_server_deploy for client-less (server)
	// grants: createServerGrant and the server-grant paths of
	// updateGrant/redeployGrant (Task 11) call it from their own
	// transaction. It is also registered as an issuance.VersionListener
	// and river worker in cmd/certforge/serve.go, not here.
	Dispatcher *deploy.Dispatcher

	// DNSTestTimeout bounds POST .../dns-credentials/{id}/test; zero means
	// the 2-minute default (a test override, since lego's Present/CleanUp
	// take no context and can't be preempted, only raced against a timer).
	DNSTestTimeout time.Duration

	// AuditVerifyTTL caches GET /audit/verify's result; zero means 60 s.
	AuditVerifyTTL time.Duration

	// Version is the running build's version string, returned by
	// getServerInfo (Phase 6A Task 2; cmd/certforge's main.version, wired
	// in cmd/certforge/serve.go). Empty answers {version: ""}.
	Version string

	// Notify is channel CRUD, send-test and the events list (Phase 6A Task
	// 6: internal/api/{channels,events}.go). Wired in cmd/certforge/serve.go
	// (Task 14), alongside the notify.DeliverWorker river registration.
	Notify *notify.Service

	// Metrics serves GET /metrics (Phase 6A Task 8: metrics.Handler, wired
	// in cmd/certforge/serve.go). nil answers 404, same as the handler
	// itself does while the "prometheus" section is disabled.
	Metrics http.Handler

	// Monitors is external-monitor CRUD and the inline check (Phase 6A
	// Task 9: internal/api/monitors.go). Wired in cmd/certforge/serve.go
	// (Task 14), alongside monitor.Service's own river registration
	// (ScanWorker/CheckWorker).
	Monitors *monitor.Service
}

// Server implements gen.StrictServerInterface, one file per resource.
type Server struct {
	d Deps

	verifyMu  sync.Mutex
	verifyAt  time.Time
	verifyRes gen.AuditChainStatus

	// vaultMu/vaultAt/vaultErr cache /readyz's "vault" sys/health probe for
	// vaultCacheTTL (Task 13); see health.go's vaultCheck.
	vaultMu  sync.Mutex
	vaultAt  time.Time
	vaultErr error

	// vaultSectionMu/vaultSectionAt/vaultSectionErr cache a second, separate
	// sys/health probe of the "vault" Integrations section's own client
	// (batch 6 review): under a Transit KEK, vaultMu above only proves the
	// KEK's own Vault is reachable, not a section configured at a different
	// address, so the two are probed and cached independently.
	vaultSectionMu  sync.Mutex
	vaultSectionAt  time.Time
	vaultSectionErr error
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
