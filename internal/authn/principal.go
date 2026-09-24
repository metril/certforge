// Package authn authenticates requests: local admin passwords, server-side
// sessions with CSRF tokens, and the Principal placed in the request context.
package authn

import (
	"context"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

// Principal kinds.
const (
	KindUser   = "user"
	KindAPIKey = "apikey"
	KindAgent  = "agent"
)

// Binding is one role, global (OrgID nil) or scoped to an org.
type Binding struct {
	Role  string
	OrgID *uuid.UUID
}

// Principal is the authenticated caller.
type Principal struct {
	Kind     string
	UserID   uuid.UUID
	Roles    []string    // distinct role names
	Bindings []Binding   // what authz.Can evaluates
	OrgIDs   []uuid.UUID // orgs the principal can see
}

type ctxKey int

const (
	principalKey ctxKey = iota
	sessionKey
)

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFrom returns the principal set by Middleware.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}

// SessionFrom returns the session behind the current request, if any.
func SessionFrom(ctx context.Context) (sqlcgen.Session, bool) {
	s, ok := ctx.Value(sessionKey).(sqlcgen.Session)
	return s, ok
}

// LoadPrincipal builds a user principal from its role bindings.
func LoadPrincipal(ctx context.Context, q *sqlcgen.Queries, u sqlcgen.User) (Principal, error) {
	rbs, err := q.ListRoleBindingsForUser(ctx, u.ID.String())
	if err != nil {
		return Principal{}, err
	}
	p := Principal{Kind: KindUser, UserID: u.ID, Roles: []string{}, Bindings: []Binding{}, OrgIDs: []uuid.UUID{}}
	seenRole := map[string]bool{}
	seenOrg := map[uuid.UUID]bool{}
	global := false
	for _, rb := range rbs {
		if rb.SiteID != nil {
			// Site scope is not modelled in Phase 1; a site-scoped binding
			// contributes nothing until site scope lands in Phase 2.
			continue
		}
		p.Bindings = append(p.Bindings, Binding{Role: rb.Role, OrgID: rb.OrgID})
		if !seenRole[rb.Role] {
			seenRole[rb.Role] = true
			p.Roles = append(p.Roles, rb.Role)
		}
		switch {
		case rb.OrgID == nil:
			global = true
		case !seenOrg[*rb.OrgID]:
			seenOrg[*rb.OrgID] = true
			p.OrgIDs = append(p.OrgIDs, *rb.OrgID)
		}
	}
	if global {
		orgs, err := q.ListOrgs(ctx)
		if err != nil {
			return Principal{}, err
		}
		p.OrgIDs = p.OrgIDs[:0]
		for _, o := range orgs {
			p.OrgIDs = append(p.OrgIDs, o.ID)
		}
	}
	return p, nil
}
