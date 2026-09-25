package api

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// ListOrgs returns the orgs visible to the caller.
func (s *Server) ListOrgs(ctx context.Context, _ gen.ListOrgsRequestObject) (gen.ListOrgsResponseObject, error) {
	p, err := authorize(ctx, authz.ActionOrgsRead, nil)
	if err != nil {
		return nil, err
	}
	orgs, err := s.d.Queries.ListOrgs(ctx)
	if err != nil {
		return nil, err
	}
	return gen.ListOrgs200JSONResponse(gen.OrgList{Items: visibleOrgs(p, orgs)}), nil
}

func visibleOrgs(p authn.Principal, orgs []sqlcgen.Org) []gen.Org {
	allowed := make(map[uuid.UUID]bool, len(p.OrgIDs))
	for _, id := range p.OrgIDs {
		allowed[id] = true
	}
	out := make([]gen.Org, 0, len(orgs))
	for _, o := range orgs {
		if allowed[o.ID] {
			out = append(out, gen.Org{Id: o.ID, Slug: o.Slug, Name: o.Name})
		}
	}
	return out
}

var orgSlugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func orgOut(o sqlcgen.Org) gen.Org { return gen.Org{Id: o.ID, Slug: o.Slug, Name: o.Name} }

func cleanName(field, name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" || len(n) > 100 {
		return "", unprocessable(field, field+" must be 1 to 100 characters")
	}
	return n, nil
}

// CreateOrg adds an organization.
func (s *Server) CreateOrg(ctx context.Context, req gen.CreateOrgRequestObject) (gen.CreateOrgResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionOrgsWrite, nil); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	if !orgSlugRE.MatchString(req.Body.Slug) || req.Body.Slug == "all" {
		return nil, unprocessable("slug", `slug must be lowercase letters, digits and hyphens, and not "all"`)
	}
	name, err := cleanName("name", req.Body.Name)
	if err != nil {
		return nil, err
	}
	o, err := s.d.Queries.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: req.Body.Slug, Name: name})
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("An org with slug %q exists.", req.Body.Slug)
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "org.create", ResourceType: "org", ResourceID: o.ID.String(), OrgID: &o.ID,
		Details: map[string]any{"slug": o.Slug, "name": o.Name}})
	return gen.CreateOrg201JSONResponse(orgOut(o)), nil
}

// UpdateOrg renames an organization; the slug is permanent.
func (s *Server) UpdateOrg(ctx context.Context, req gen.UpdateOrgRequestObject) (gen.UpdateOrgResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionOrgsWrite, nil); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	cur, err := s.d.Queries.GetOrg(ctx, req.OrgId)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("org %s", req.OrgId)
	}
	if err != nil {
		return nil, err
	}
	if req.Body.Slug != nil && *req.Body.Slug != cur.Slug {
		return nil, unprocessable("slug", "the slug cannot change")
	}
	name, err := cleanName("name", req.Body.Name)
	if err != nil {
		return nil, err
	}
	o, err := s.d.Queries.UpdateOrgName(ctx, sqlcgen.UpdateOrgNameParams{ID: cur.ID, Name: name})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "org.update", ResourceType: "org", ResourceID: o.ID.String(), OrgID: &o.ID,
		Details: map[string]any{"before": map[string]any{"name": cur.Name}, "after": map[string]any{"name": o.Name}}})
	return gen.UpdateOrg200JSONResponse(orgOut(o)), nil
}

// DeleteOrg removes an org that has no dependents (certificates, DNS
// credentials, ACME accounts, CAs, sites, role bindings, active API keys,
// clients, layouts, deploy targets, or hooks). The org's own
// issuance-defaults row and its revoked API keys are removed along with
// it. The row lock serializes against concurrent inserts, whose
// foreign-key checks need a key-share lock.
func (s *Server) DeleteOrg(ctx context.Context, req gen.DeleteOrgRequestObject) (gen.DeleteOrgResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionOrgsWrite, nil); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	if _, err := q.LockOrg(ctx, req.OrgId); errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("org %s", req.OrgId)
	} else if err != nil {
		return nil, err
	}
	d, err := q.CountOrgDependents(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, c := range []struct {
		n    int64
		noun string
	}{{d.Certificates, "certificate"}, {d.DnsCredentials, "DNS credential"}, {d.AcmeAccounts, "ACME account"},
		{d.Cas, "CA"}, {d.Sites, "site"}, {d.RoleBindings, "role binding"}, {d.ApiKeys, "API key"},
		{d.Clients, "client"}, {d.Layouts, "layout"}, {d.DeployTargets, "deploy target"}, {d.Hooks, "hook"}} {
		if c.n == 1 {
			parts = append(parts, "1 "+c.noun)
		} else if c.n > 1 {
			parts = append(parts, fmt.Sprintf("%d %ss", c.n, c.noun))
		}
	}
	if len(parts) > 0 {
		return nil, conflict("Delete these first: %s. Its issuance defaults and revoked API keys are removed with the org.", strings.Join(parts, ", "))
	}
	o, err := q.GetOrg(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if err := q.DeleteOrg(ctx, req.OrgId); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "org.delete", ResourceType: "org", ResourceID: o.ID.String(), OrgID: &o.ID,
		Details: map[string]any{"slug": o.Slug, "name": o.Name}})
	return gen.DeleteOrg204Response{}, nil
}
