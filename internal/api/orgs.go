package api

import (
	"context"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
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
