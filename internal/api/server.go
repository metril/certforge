// Package api wires the HTTP surface: the generated strict server, auth
// middleware, problem+json errors, the OpenAPI document, and health checks.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/config"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/meta"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/setup"
)

// Deps are the services handlers use.
type Deps struct {
	Config   config.Config
	Log      *slog.Logger
	Pool     *pgxpool.Pool
	Queries  *sqlcgen.Queries
	Settings *settings.Store
	Sections *settings.Registry
	Meta     *meta.Registry
	Sessions *authn.Sessions
	Auditor  *audit.Auditor
	Setup    *setup.Service
	Issuance *issuance.Service // Store, certstore and the river job queue (Tasks 12-14)
}

// Server implements gen.StrictServerInterface, one file per resource.
type Server struct {
	d Deps
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
