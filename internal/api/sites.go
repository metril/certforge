package api

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func siteOut(s sqlcgen.Site, clients int64) gen.Site {
	return gen.Site{Id: s.ID, OrgId: s.OrgID, Name: s.Name, ClientCount: clients, CreatedAt: s.CreatedAt}
}

// ListSites returns an org's sites with the number of clients at each.
func (s *Server) ListSites(ctx context.Context, req gen.ListSitesRequestObject) (gen.ListSitesResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSitesRead, &req.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.d.Queries.ListSitesWithClientCount(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]gen.Site, 0, len(rows))
	for _, r := range rows {
		out = append(out, siteOut(sqlcgen.Site{ID: r.ID, OrgID: r.OrgID, Name: r.Name, CreatedAt: r.CreatedAt}, r.ClientCount))
	}
	return gen.ListSites200JSONResponse(gen.SiteList{Items: out}), nil
}

// CreateSite adds a site to an org.
func (s *Server) CreateSite(ctx context.Context, req gen.CreateSiteRequestObject) (gen.CreateSiteResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSitesWrite, &req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	name, err := cleanName("name", req.Body.Name)
	if err != nil {
		return nil, err
	}
	site, err := s.d.Queries.CreateSite(ctx, sqlcgen.CreateSiteParams{OrgID: req.OrgId, Name: name})
	switch pgCode(err) {
	case pgUniqueViolation:
		return nil, conflict("A site named %q exists in this org.", name)
	case pgForeignKeyViolation:
		return nil, notFound("org %s", req.OrgId)
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "site.create", ResourceType: "site", ResourceID: site.ID.String(), OrgID: &site.OrgID,
		Details: map[string]any{"name": site.Name}})
	return gen.CreateSite201JSONResponse(siteOut(site, 0)), nil
}

// UpdateSite renames a site.
func (s *Server) UpdateSite(ctx context.Context, req gen.UpdateSiteRequestObject) (gen.UpdateSiteResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSitesWrite, &req.OrgId); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	name, err := cleanName("name", req.Body.Name)
	if err != nil {
		return nil, err
	}
	cur, err := s.d.Queries.GetSite(ctx, sqlcgen.GetSiteParams{ID: req.Id, OrgID: req.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("site %s", req.Id)
	}
	if err != nil {
		return nil, err
	}
	site, err := s.d.Queries.UpdateSiteName(ctx, sqlcgen.UpdateSiteNameParams{Name: name, ID: req.Id, OrgID: req.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("site %s", req.Id)
	}
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("A site named %q exists in this org.", name)
	}
	if err != nil {
		return nil, err
	}
	clients, err := s.d.Queries.CountSiteClients(ctx, sqlcgen.CountSiteClientsParams{SiteID: &site.ID, OrgID: site.OrgID})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "site.update", ResourceType: "site", ResourceID: site.ID.String(), OrgID: &site.OrgID,
		Details: map[string]any{"before": map[string]any{"name": cur.Name}, "after": map[string]any{"name": site.Name}}})
	return gen.UpdateSite200JSONResponse(siteOut(site, clients)), nil
}

// DeleteSite removes a site. Its clients are detached (site_id ON DELETE SET
// NULL), not deleted; the audit detail records how many.
func (s *Server) DeleteSite(ctx context.Context, req gen.DeleteSiteRequestObject) (gen.DeleteSiteResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSitesWrite, &req.OrgId); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	detached, err := q.CountSiteClients(ctx, sqlcgen.CountSiteClientsParams{SiteID: &req.Id, OrgID: req.OrgId})
	if err != nil {
		return nil, err
	}
	n, err := q.DeleteSite(ctx, sqlcgen.DeleteSiteParams{ID: req.Id, OrgID: req.OrgId})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, notFound("site %s", req.Id)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "site.delete", ResourceType: "site", ResourceID: req.Id.String(), OrgID: &req.OrgId,
		Details: map[string]any{"detachedClients": detached}})
	return gen.DeleteSite204Response{}, nil
}
