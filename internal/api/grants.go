package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func deploymentOut(state string, versionID *uuid.UUID, expected, installed []byte, errText string, reportedAt *time.Time, updatedAt time.Time) (gen.Deployment, error) {
	var exp []agentproto.FileSpec
	if err := json.Unmarshal(expected, &exp); err != nil {
		return gen.Deployment{}, err
	}
	var inst []agentproto.FileDigest
	if err := json.Unmarshal(installed, &inst); err != nil {
		return gen.Deployment{}, err
	}
	d := gen.Deployment{State: gen.DeploymentState(state), VersionId: versionID, Expected: make([]gen.FileDigest, 0, len(exp)),
		Installed: make([]gen.FileDigest, 0, len(inst)), Error: errText, ReportedAt: reportedAt, UpdatedAt: updatedAt}
	for _, e := range exp {
		d.Expected = append(d.Expected, gen.FileDigest{Path: e.Path, Sha256: e.SHA256})
	}
	for _, i := range inst {
		d.Installed = append(d.Installed, gen.FileDigest{Path: i.Path, Sha256: i.SHA256})
	}
	return d, nil
}

func grantOut(r sqlcgen.GrantViewsRow) (gen.Grant, error) {
	d, err := deploymentOut(r.State, r.VersionID, r.Expected, r.Installed, r.Error, r.ReportedAt, r.DeploymentUpdatedAt)
	if err != nil {
		return gen.Grant{}, err
	}
	return gen.Grant{Id: r.ID, ClientId: *r.ClientID, ClientName: r.ClientName, CertificateId: r.CertID, CertificateName: r.CertificateName,
		Delivery: gen.GrantDelivery(r.Delivery), LayoutId: r.OutputSpecID, DeployTargetId: r.DeployTargetID, HookIds: r.HookIds,
		AutoRemediate: r.AutoRemediate, Deployment: d, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}, nil
}

func (s *Server) grantByID(ctx context.Context, orgID, id uuid.UUID) (gen.Grant, error) {
	rows, err := s.queries().GrantViews(ctx, sqlcgen.GrantViewsParams{OrgID: orgID, GrantID: &id})
	if err != nil {
		return gen.Grant{}, err
	}
	if len(rows) == 0 {
		return gen.Grant{}, notFound("grant %s", id)
	}
	return grantOut(rows[0])
}

// ListClientGrants returns a client's live grants.
func (s *Server) ListClientGrants(ctx context.Context, r gen.ListClientGrantsRequestObject) (gen.ListClientGrantsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsRead, &r.OrgId); err != nil {
		return nil, err
	}
	if _, err := s.queries().GetClient(ctx, sqlcgen.GetClientParams{ID: r.Id, OrgID: r.OrgId}); errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("client %s", r.Id)
	} else if err != nil {
		return nil, err
	}
	rows, err := s.queries().GrantViews(ctx, sqlcgen.GrantViewsParams{OrgID: r.OrgId, ClientID: &r.Id})
	if err != nil {
		return nil, err
	}
	items := make([]gen.Grant, 0, len(rows))
	for _, row := range rows {
		g, err := grantOut(row)
		if err != nil {
			return nil, err
		}
		items = append(items, g)
	}
	return gen.ListClientGrants200JSONResponse(gen.GrantList{Items: items}), nil
}

// CreateGrant grants a certificate to a client.
func (s *Server) CreateGrant(ctx context.Context, r gen.CreateGrantRequestObject) (gen.CreateGrantResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, badRequest("missing body")
	}
	in := agents.GrantInput{CertID: r.Body.CertificateId, Delivery: string(r.Body.Delivery), LayoutID: r.Body.LayoutId, TargetID: r.Body.DeployTargetId}
	if r.Body.HookIds != nil {
		in.HookIDs = *r.Body.HookIds
	}
	if r.Body.AutoRemediate != nil {
		in.AutoRemediate = *r.Body.AutoRemediate
	}
	id, err := s.d.Agents.CreateGrant(ctx, r.OrgId, r.Id, in)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	g, err := s.grantByID(ctx, r.OrgId, id)
	if err != nil {
		return nil, err
	}
	return gen.CreateGrant201JSONResponse(g), nil
}

// UpdateGrant replaces a grant's delivery settings.
func (s *Server) UpdateGrant(ctx context.Context, r gen.UpdateGrantRequestObject) (gen.UpdateGrantResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, badRequest("missing body")
	}
	in := agents.GrantInput{Delivery: string(r.Body.Delivery), LayoutID: r.Body.LayoutId, TargetID: r.Body.DeployTargetId,
		HookIDs: r.Body.HookIds, AutoRemediate: r.Body.AutoRemediate}
	if err := s.d.Agents.UpdateGrant(ctx, r.OrgId, r.Id, in); err != nil {
		return nil, mapAgentErr(err)
	}
	g, err := s.grantByID(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, err
	}
	return gen.UpdateGrant200JSONResponse(g), nil
}

// DeleteGrant removes a grant (via the agent when it is enrolled, or at
// once when force is set).
func (s *Server) DeleteGrant(ctx context.Context, r gen.DeleteGrantRequestObject) (gen.DeleteGrantResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	force := r.Params.Force != nil && *r.Params.Force
	if err := s.d.Agents.DeleteGrant(ctx, r.OrgId, r.Id, force); err != nil {
		return nil, mapAgentErr(err)
	}
	return gen.DeleteGrant204Response{}, nil
}

// RedeployGrant marks a grant pending and nudges its agent.
func (s *Server) RedeployGrant(ctx context.Context, r gen.RedeployGrantRequestObject) (gen.RedeployGrantResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if err := s.d.Agents.Redeploy(ctx, r.OrgId, r.Id); err != nil {
		return nil, mapAgentErr(err)
	}
	g, err := s.grantByID(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, err
	}
	return gen.RedeployGrant200JSONResponse(g), nil
}

// ListCertificateDeployments returns one row per live grant of a certificate.
func (s *Server) ListCertificateDeployments(ctx context.Context, r gen.ListCertificateDeploymentsRequestObject) (gen.ListCertificateDeploymentsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsRead, &r.OrgId); err != nil {
		return nil, err
	}
	q := s.queries()
	ok, err := q.CertificateInOrg(ctx, sqlcgen.CertificateInOrgParams{ID: r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, notFound("certificate %s", r.Id)
	}
	rows, err := q.CertificateDeployments(ctx, sqlcgen.CertificateDeploymentsParams{CertID: r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	var cutoff time.Time
	if s.d.Agents != nil {
		cutoff = s.d.Agents.OnlineCutoff(ctx)
	}
	items := make([]gen.CertificateDeployment, 0, len(rows))
	for _, row := range rows {
		connected := s.d.Agents != nil && s.d.Agents.Connected(*row.ClientID)
		online := connected || (s.d.Agents != nil && row.ClientLastSeen != nil && !row.ClientLastSeen.Before(cutoff))
		d, err := deploymentOut(row.State, row.VersionID, row.Expected, row.Installed, row.Error, row.ReportedAt, row.DeploymentUpdatedAt)
		if err != nil {
			return nil, err
		}
		items = append(items, gen.CertificateDeployment{GrantId: row.GrantID, ClientId: *row.ClientID, ClientName: row.ClientName,
			ClientStatus: gen.ClientStatus(row.ClientStatus), ClientConnected: connected, ClientOnline: online,
			SiteId: row.SiteID, Delivery: gen.GrantDelivery(row.Delivery), LayoutId: row.LayoutID, LayoutName: row.LayoutName,
			DeployTargetId: row.DeployTargetID, DeployTargetName: row.DeployTargetName, Deployment: d})
	}
	return gen.ListCertificateDeployments200JSONResponse(gen.CertificateDeploymentList{Items: items}), nil
}

// addGrantCounts sets grantCount on certificate list items.
func (s *Server) addGrantCounts(ctx context.Context, items []gen.Certificate) error {
	ids := make([]uuid.UUID, len(items))
	for i, c := range items {
		ids[i] = c.Id
	}
	rows, err := s.queries().CountLiveGrantsByCert(ctx, ids)
	if err != nil {
		return err
	}
	m := make(map[uuid.UUID]int, len(rows))
	for _, r := range rows {
		m[r.CertID] = int(r.Grants)
	}
	for i := range items {
		n := m[items[i].Id]
		items[i].GrantCount = &n
	}
	return nil
}
