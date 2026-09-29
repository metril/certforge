package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
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

// grantOut maps a GrantViews row to its API shape. GrantViews only ever
// returns client grants (its query joins clients): clientId and clientName
// are always set, deployment is always present, and runsOn is always agent
// with serverDeployment nil. serverGrantOut is its server-grant
// counterpart, from ServerGrantViews.
func grantOut(r sqlcgen.GrantViewsRow) (gen.Grant, error) {
	d, err := deploymentOut(r.State, r.VersionID, r.Expected, r.Installed, r.Error, r.ReportedAt, r.DeploymentUpdatedAt)
	if err != nil {
		return gen.Grant{}, err
	}
	clientName := r.ClientName
	return gen.Grant{Id: r.ID, ClientId: r.ClientID, ClientName: &clientName, CertificateId: r.CertID, CertificateName: r.CertificateName,
		Delivery: gen.GrantDelivery(r.Delivery), LayoutId: r.OutputSpecID, DeployTargetId: r.DeployTargetID, HookIds: r.HookIds,
		AutoRemediate: r.AutoRemediate, Deployment: &d, RunsOn: gen.RunsOn("agent"), ServerDeployment: nil,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}, nil
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

// UpdateGrant replaces a grant's delivery settings (a client grant), or,
// for a server grant, its layout — the only field it takes (Shared
// contract).
func (s *Server) UpdateGrant(ctx context.Context, r gen.UpdateGrantRequestObject) (gen.UpdateGrantResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, badRequest("missing body")
	}
	runsOn, err := s.grantRunsOn(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, err
	}
	if runsOn == "server" {
		return s.updateServerGrant(ctx, r)
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

// DeleteGrant removes a grant: via the agent when it is enrolled, or at
// once when force is set (a client grant), or always at once (a server
// grant: there is no agent to confirm removal).
func (s *Server) DeleteGrant(ctx context.Context, r gen.DeleteGrantRequestObject) (gen.DeleteGrantResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	runsOn, err := s.grantRunsOn(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, err
	}
	if runsOn == "server" {
		if err := s.deleteServerGrant(ctx, r.OrgId, r.Id); err != nil {
			return nil, err
		}
		return gen.DeleteGrant204Response{}, nil
	}
	force := r.Params.Force != nil && *r.Params.Force
	if err := s.d.Agents.DeleteGrant(ctx, r.OrgId, r.Id, force); err != nil {
		return nil, mapAgentErr(err)
	}
	return gen.DeleteGrant204Response{}, nil
}

// RedeployGrant marks a grant pending and nudges its agent (a client
// grant), or marks it pending and enqueues certforge_server_deploy (a
// server grant).
func (s *Server) RedeployGrant(ctx context.Context, r gen.RedeployGrantRequestObject) (gen.RedeployGrantResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	runsOn, err := s.grantRunsOn(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, err
	}
	if runsOn == "server" {
		return s.redeployServerGrant(ctx, r)
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
	// row.ClientID is a *uuid.UUID only because client_cert_grants.client_id
	// became nullable for server grants (Task 11); CertificateDeployments'
	// own query INNER JOINs clients, which a server grant's NULL client_id
	// can never match, so every row here is a client grant and the
	// dereference below is always safe. CertificateDeployment's own schema
	// (ClientId required, Deployment required) was intentionally left
	// unchanged for 5A: a server grant's status shows on the deploy
	// target instead (ServerGrantViews/ListTargetGrants), not here.
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

// ---- server grants (Task 11: client-less grants on a server-run deploy
// target, deployed by internal/deploy.Dispatcher instead of an agent).

// serverGrantOut maps a ServerGrantViews row to its API shape: clientId,
// clientName and deployment are always nil, runsOn is always server.
func serverGrantOut(r sqlcgen.ServerGrantViewsRow) gen.Grant {
	var sd *gen.ServerDeployment
	if r.Status != nil {
		var lastError *string
		if r.LastError != nil && *r.LastError != "" {
			lastError = r.LastError
		}
		updatedAt := r.UpdatedAt
		if r.DeploymentUpdatedAt != nil {
			updatedAt = *r.DeploymentUpdatedAt
		}
		sd = &gen.ServerDeployment{Status: gen.ServerDeploymentStatus(*r.Status), VersionId: r.VersionID,
			LastError: lastError, DeployedAt: r.DeployedAt, UpdatedAt: updatedAt}
	}
	return gen.Grant{Id: r.ID, ClientId: nil, ClientName: nil, CertificateId: r.CertID, CertificateName: r.CertificateName,
		Delivery: gen.GrantDelivery(r.Delivery), LayoutId: r.OutputSpecID, DeployTargetId: r.DeployTargetID, HookIds: r.HookIds,
		AutoRemediate: r.AutoRemediate, Deployment: nil, RunsOn: gen.RunsOn("server"), ServerDeployment: sd,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

func (s *Server) serverGrantByID(ctx context.Context, orgID, id uuid.UUID) (gen.Grant, error) {
	rows, err := s.queries().ServerGrantViews(ctx, sqlcgen.ServerGrantViewsParams{OrgID: orgID, GrantID: &id})
	if err != nil {
		return gen.Grant{}, err
	}
	if len(rows) == 0 {
		return gen.Grant{}, notFound("grant %s", id)
	}
	return serverGrantOut(rows[0]), nil
}

// grantRunsOn tells updateGrant/deleteGrant/redeployGrant which kind id is,
// org-scoped (pre-flight ruling): pgx.ErrNoRows means id is not a live
// grant of orgId at all, either kind, a 404.
func (s *Server) grantRunsOn(ctx context.Context, orgID, id uuid.UUID) (string, error) {
	v, err := s.queries().GrantRunsOn(ctx, sqlcgen.GrantRunsOnParams{ID: id, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", notFound("grant %s", id)
	}
	return v, err
}

// serverLayoutFiles locks layoutID (org-scoped) and returns its parsed
// files, refusing anything but a PEM-only layout (Shared contract: a
// server grant's layout may only render pem files — no p12/jks/der).
func serverLayoutFiles(ctx context.Context, q *sqlcgen.Queries, orgID, layoutID uuid.UUID) ([]delivery.OutputFile, error) {
	lo, err := q.LockLayoutForGrant(ctx, sqlcgen.LockLayoutForGrantParams{ID: layoutID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, unprocessable("layoutId", fmt.Sprintf("layout %s is not in this org", layoutID))
	} else if err != nil {
		return nil, err
	}
	var files []delivery.OutputFile
	if err := json.Unmarshal(lo.Files, &files); err != nil {
		return nil, err
	}
	for _, f := range files {
		if f.Format != "pem" {
			return nil, unprocessable("layoutId", "a server grant's layout may only render pem files")
		}
	}
	return files, nil
}

// includeKeyOf reads a server-run target's own includeKey config field
// (only vault-kv has one today; any future type that doesn't is treated as
// false, never needing a key).
func includeKeyOf(cfg []byte) (bool, error) {
	var c struct {
		IncludeKey bool `json:"includeKey"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		return false, err
	}
	return c.IncludeKey, nil
}

// CreateServerGrant grants a certificate to a server-run deploy target.
func (s *Server) CreateServerGrant(ctx context.Context, r gen.CreateServerGrantRequestObject) (gen.CreateServerGrantResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, badRequest("missing body")
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.queries().WithTx(tx)

	target, err := q.LockServerTarget(ctx, sqlcgen.LockServerTargetParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("deploy target %s", r.Id)
	} else if err != nil {
		return nil, err
	}
	if target.RunsOn != "server" {
		return nil, unprocessable("deployTargetId", "deploy target runs on an agent, not the server")
	}
	if _, err := q.LockCertificateForGrant(ctx, sqlcgen.LockCertificateForGrantParams{ID: r.Body.CertificateId, OrgID: r.OrgId}); errors.Is(err, pgx.ErrNoRows) {
		return nil, unprocessable("certificateId", fmt.Sprintf("certificate %s is not in this org", r.Body.CertificateId))
	} else if err != nil {
		return nil, err
	}
	var layoutFiles []delivery.OutputFile
	if r.Body.LayoutId != nil {
		if layoutFiles, err = serverLayoutFiles(ctx, q, r.OrgId, *r.Body.LayoutId); err != nil {
			return nil, err
		}
	}
	includeKey, err := includeKeyOf(target.Config)
	if err != nil {
		return nil, err
	}
	needsKey := includeKey || delivery.NeedsKey(layoutFiles)
	if needsKey {
		if _, err := authorize(ctx, authz.ActionKeysExport, &r.OrgId); err != nil {
			return nil, err
		}
		st, err := q.CertificateCurrentHasKey(ctx, r.Body.CertificateId)
		if err != nil {
			return nil, err
		}
		if st.HasVersion && !st.HasKey {
			return nil, unprocessable("certificateId", fmt.Sprintf("certificate %s has no stored private key; its layout or target needs one", r.Body.CertificateId))
		}
	}

	g, err := q.CreateServerGrant(ctx, sqlcgen.CreateServerGrantParams{CertID: r.Body.CertificateId, OutputSpecID: r.Body.LayoutId, DeployTargetID: &r.Id})
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("This target already has a grant for that certificate.")
	}
	if err != nil {
		return nil, err
	}
	versionID, err := q.CertificateCurrentVersion(ctx, r.Body.CertificateId)
	if err != nil {
		return nil, err
	}
	if err := s.d.Dispatcher.EnqueueTx(ctx, tx, q, g.ID, versionID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "grant.create", ResourceType: "grant", ResourceID: g.ID.String(), OrgID: &r.OrgId,
		Details: map[string]any{"deployTargetId": r.Id, "certificateId": r.Body.CertificateId, "layoutId": r.Body.LayoutId,
			"runsOn": "server", "includeKey": includeKey}})
	out, err := s.serverGrantByID(ctx, r.OrgId, g.ID)
	if err != nil {
		return nil, err
	}
	return gen.CreateServerGrant201JSONResponse(out), nil
}

// ListTargetGrants returns a server-run deploy target's live grants.
func (s *Server) ListTargetGrants(ctx context.Context, r gen.ListTargetGrantsRequestObject) (gen.ListTargetGrantsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsRead, &r.OrgId); err != nil {
		return nil, err
	}
	if _, err := s.queries().GetDeployTarget(ctx, sqlcgen.GetDeployTargetParams{ID: r.Id, OrgID: r.OrgId}); errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("deploy target %s", r.Id)
	} else if err != nil {
		return nil, err
	}
	rows, err := s.queries().ServerGrantViews(ctx, sqlcgen.ServerGrantViewsParams{OrgID: r.OrgId, TargetID: &r.Id})
	if err != nil {
		return nil, err
	}
	items := make(gen.ListTargetGrants200JSONResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, serverGrantOut(row))
	}
	return items, nil
}

// updateServerGrant replaces a server grant's layout (its only editable
// field) and re-renders its current version under it.
func (s *Server) updateServerGrant(ctx context.Context, r gen.UpdateGrantRequestObject) (gen.UpdateGrantResponseObject, error) {
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.queries().WithTx(tx)

	g, err := q.LockServerGrant(ctx, sqlcgen.LockServerGrantParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("grant %s", r.Id)
	} else if err != nil {
		return nil, err
	}
	var layoutID *uuid.UUID
	if r.Body != nil {
		layoutID = r.Body.LayoutId
	}
	if layoutID != nil {
		if _, err := serverLayoutFiles(ctx, q, r.OrgId, *layoutID); err != nil {
			return nil, err
		}
	}
	if _, err := q.UpdateServerGrantLayout(ctx, sqlcgen.UpdateServerGrantLayoutParams{ID: r.Id, OutputSpecID: layoutID}); err != nil {
		return nil, err
	}
	versionID, err := q.CertificateCurrentVersion(ctx, g.CertID)
	if err != nil {
		return nil, err
	}
	if err := s.d.Dispatcher.EnqueueTx(ctx, tx, q, r.Id, versionID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "grant.update", ResourceType: "grant", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: map[string]any{"before": map[string]any{"layoutId": g.OutputSpecID}, "after": map[string]any{"layoutId": layoutID}, "runsOn": "server"}})
	out, err := s.serverGrantByID(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, err
	}
	return gen.UpdateGrant200JSONResponse(out), nil
}

// deleteServerGrant removes a server grant at once: there is no agent to
// confirm removal, so there is no soft-delete path (client_cert_grants'
// removed_at) the way DeleteGrant has for a client grant. The cascade on
// server_deployments (ON DELETE CASCADE) removes its deployment row too.
func (s *Server) deleteServerGrant(ctx context.Context, orgID, id uuid.UUID) error {
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.queries().WithTx(tx)
	g, err := q.LockServerGrant(ctx, sqlcgen.LockServerGrantParams{ID: id, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return notFound("grant %s", id)
	} else if err != nil {
		return err
	}
	if err := q.DeleteGrantRow(ctx, id); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.audit(ctx, audit.Event{Action: "grant.delete", ResourceType: "grant", ResourceID: id.String(), OrgID: &orgID,
		Details: map[string]any{"deployTargetId": g.DeployTargetID, "certificateId": g.CertID, "runsOn": "server"}})
	return nil
}

// redeployServerGrant marks a server grant pending on its certificate's
// current version and enqueues certforge_server_deploy for it.
func (s *Server) redeployServerGrant(ctx context.Context, r gen.RedeployGrantRequestObject) (gen.RedeployGrantResponseObject, error) {
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.queries().WithTx(tx)
	g, err := q.LockServerGrant(ctx, sqlcgen.LockServerGrantParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("grant %s", r.Id)
	} else if err != nil {
		return nil, err
	}
	versionID, err := q.CertificateCurrentVersion(ctx, g.CertID)
	if err != nil {
		return nil, err
	}
	if err := s.d.Dispatcher.EnqueueTx(ctx, tx, q, r.Id, versionID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "grant.redeploy", ResourceType: "grant", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: map[string]any{"deployTargetId": g.DeployTargetID, "certificateId": g.CertID, "runsOn": "server"}})
	out, err := s.serverGrantByID(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, err
	}
	return gen.RedeployGrant200JSONResponse(out), nil
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
