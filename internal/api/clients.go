package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// mapAgentErr turns an agents.Error into the matching problem response.
func mapAgentErr(err error) error {
	var ae *agents.Error
	if !errors.As(err, &ae) {
		return err
	}
	switch ae.Kind {
	case agents.KindNotFound:
		return notFound("%s", ae.Detail)
	case agents.KindConflict:
		return conflict("%s", ae.Detail)
	case agents.KindInvalid:
		return unprocessable(ae.Field, ae.Detail)
	case agents.KindUnauthorized:
		return &HTTPError{Status: http.StatusUnauthorized, Title: "Unauthorized", Detail: ae.Detail}
	}
	return err
}

func clientFromRow(r sqlcgen.ListClientsRow) sqlcgen.Client {
	return sqlcgen.Client{ID: r.ID, OrgID: r.OrgID, SiteID: r.SiteID, Name: r.Name, Status: r.Status,
		AgentCertSerial: r.AgentCertSerial, AgentCertNotAfter: r.AgentCertNotAfter, AgentCaID: r.AgentCaID,
		Hostname: r.Hostname, Os: r.Os, Arch: r.Arch, AgentVersion: r.AgentVersion, Capabilities: r.Capabilities,
		LastSeen: r.LastSeen, DesiredRevision: r.DesiredRevision, AppliedRevision: r.AppliedRevision, CreatedAt: r.CreatedAt}
}

// clientsOut adds grant counts, token expiry and connection state (connected:
// socket membership; online: connected or seen within offlineAfterSeconds).
func (s *Server) clientsOut(ctx context.Context, rows []sqlcgen.Client) ([]gen.Client, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, c := range rows {
		ids[i] = c.ID
	}
	q := s.queries()
	counts, err := q.ClientCounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	tokens, err := q.PendingTokens(ctx, ids)
	if err != nil {
		return nil, err
	}
	cm := map[uuid.UUID]sqlcgen.ClientCountsRow{}
	for _, c := range counts {
		cm[c.ClientID] = c
	}
	em := map[uuid.UUID]time.Time{}
	for _, t := range tokens {
		if t.ExpiresAt.After(em[t.ClientID]) {
			em[t.ClientID] = t.ExpiresAt
		}
	}
	var cutoff time.Time
	if s.d.Agents != nil {
		cutoff = s.d.Agents.OnlineCutoff(ctx)
	}
	out := make([]gen.Client, 0, len(rows))
	for _, c := range rows {
		n := cm[c.ID]
		connected := s.d.Agents != nil && s.d.Agents.Connected(c.ID)
		online := connected || (s.d.Agents != nil && c.LastSeen != nil && !c.LastSeen.Before(cutoff))
		g := gen.Client{Id: c.ID, OrgId: c.OrgID, SiteId: c.SiteID, Name: c.Name, Status: gen.ClientStatus(c.Status),
			Connected: connected, Online: online, Hostname: c.Hostname, Os: c.Os, Arch: c.Arch,
			AgentVersion: c.AgentVersion, Capabilities: c.Capabilities, LastSeen: c.LastSeen,
			AgentCertNotAfter: c.AgentCertNotAfter, DesiredRevision: c.DesiredRevision, AppliedRevision: c.AppliedRevision,
			GrantCount: int(n.Grants), DriftCount: int(n.Drift), FailedCount: int(n.Failed), CreatedAt: c.CreatedAt}
		if exp, ok := em[c.ID]; ok && c.Status == "pending" {
			g.TokenExpiresAt = &exp
		}
		out = append(out, g)
	}
	return out, nil
}

func (s *Server) clientOut(ctx context.Context, c sqlcgen.Client) (gen.Client, error) {
	out, err := s.clientsOut(ctx, []sqlcgen.Client{c})
	if err != nil {
		return gen.Client{}, err
	}
	return out[0], nil
}

var clientSortFields = []string{"lastSeen", "name", "status"}

// clientCursor binds a keyset position to the request that produced it.
type clientCursor struct {
	Sort    string    `json:"sort"`
	Desc    bool      `json:"desc"`
	Q       string    `json:"q"`
	Status  string    `json:"status"`
	Site    string    `json:"site"`
	LastKey string    `json:"lastKey"`
	LastID  uuid.UUID `json:"lastId"`
}

type clientListParams struct {
	site      *uuid.UUID
	status, q string
	sort      string
	desc      bool
	limit     int
	cursor    *clientCursor
}

func siteKey(s *uuid.UUID) string {
	if s == nil {
		return ""
	}
	return s.String()
}

func parseClientList(site *uuid.UUID, status *gen.ClientStatus, q, sort *string, limit *int, cursor *string) (clientListParams, error) {
	p := clientListParams{site: site, sort: "name", limit: 50}
	if status != nil {
		p.status = string(*status)
		if !slices.Contains([]string{"pending", "active", "revoked"}, p.status) {
			return p, unprocessable("status", "status must be pending, active or revoked")
		}
	}
	if q != nil {
		p.q = strings.ToLower(strings.TrimSpace(*q))
	}
	raw := "name"
	if sort != nil && *sort != "" {
		raw = *sort
	}
	p.desc = strings.HasPrefix(raw, "-")
	p.sort = strings.TrimPrefix(raw, "-")
	if !slices.Contains(clientSortFields, p.sort) {
		return p, unprocessable("sort", "sort by one of "+strings.Join(clientSortFields, ", "))
	}
	if limit != nil {
		if *limit < 1 || *limit > 500 {
			return p, unprocessable("limit", "limit must be 1 to 500")
		}
		p.limit = *limit
	}
	if cursor != nil && *cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(*cursor)
		var c clientCursor
		if err != nil || json.Unmarshal(b, &c) != nil {
			return p, unprocessable("cursor", "cursor is not from this list")
		}
		if c.Sort != p.sort || c.Desc != p.desc || c.Q != p.q || c.Status != p.status || c.Site != siteKey(site) {
			return p, unprocessable("cursor", "cursor does not match this request's site, status, q, or sort")
		}
		p.cursor = &c
	}
	return p, nil
}

func (s *Server) listClients(ctx context.Context, orgIDs []uuid.UUID, p clientListParams) (gen.ClientList, error) {
	arg := sqlcgen.ListClientsParams{Sort: p.sort, OrgIds: orgIDs, SiteID: p.site, Status: p.status, Q: p.q,
		Descending: p.desc, PageLimit: int32(p.limit + 1)}
	if p.cursor != nil {
		arg.HasCursor, arg.AfterKey, arg.AfterID = true, p.cursor.LastKey, p.cursor.LastID
	}
	rows, err := s.queries().ListClients(ctx, arg)
	if err != nil {
		return gen.ClientList{}, err
	}
	var next *string
	if len(rows) > p.limit {
		rows = rows[:p.limit]
		last := rows[len(rows)-1]
		b, _ := json.Marshal(clientCursor{Sort: p.sort, Desc: p.desc, Q: p.q, Status: p.status, Site: siteKey(p.site),
			LastKey: last.SortKey, LastID: last.ID})
		n := base64.RawURLEncoding.EncodeToString(b)
		next = &n
	}
	clients := make([]sqlcgen.Client, len(rows))
	for i, r := range rows {
		clients[i] = clientFromRow(r)
	}
	items, err := s.clientsOut(ctx, clients)
	if err != nil {
		return gen.ClientList{}, err
	}
	return gen.ClientList{Items: items, NextCursor: next}, nil
}

// ListClients returns one page of an org's clients.
func (s *Server) ListClients(ctx context.Context, r gen.ListClientsRequestObject) (gen.ListClientsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsRead, &r.OrgId); err != nil {
		return nil, err
	}
	p, err := parseClientList(r.Params.Site, r.Params.Status, r.Params.Q, r.Params.Sort, r.Params.Limit, r.Params.Cursor)
	if err != nil {
		return nil, err
	}
	out, err := s.listClients(ctx, []uuid.UUID{r.OrgId}, p)
	if err != nil {
		return nil, err
	}
	return gen.ListClients200JSONResponse(out), nil
}

// ListAllClients lists clients across every org the caller can read.
func (s *Server) ListAllClients(ctx context.Context, r gen.ListAllClientsRequestObject) (gen.ListAllClientsResponseObject, error) {
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	orgs := authz.OrgsWith(p, authz.ActionClientsRead)
	if len(orgs) == 0 {
		return nil, &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "missing permission clients:read"}
	}
	lp, err := parseClientList(r.Params.Site, r.Params.Status, r.Params.Q, r.Params.Sort, r.Params.Limit, r.Params.Cursor)
	if err != nil {
		return nil, err
	}
	out, err := s.listClients(ctx, orgs, lp)
	if err != nil {
		return nil, err
	}
	return gen.ListAllClients200JSONResponse(out), nil
}

// GetClient returns one client.
func (s *Server) GetClient(ctx context.Context, r gen.GetClientRequestObject) (gen.GetClientResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsRead, &r.OrgId); err != nil {
		return nil, err
	}
	c, err := s.queries().GetClient(ctx, sqlcgen.GetClientParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("client %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	out, err := s.clientOut(ctx, c)
	if err != nil {
		return nil, err
	}
	return gen.GetClient200JSONResponse(out), nil
}

func (s *Server) enrolmentOut(ctx context.Context, e agents.Enrolment) (gen.ClientCreated, error) {
	c, err := s.clientOut(ctx, e.Client)
	if err != nil {
		return gen.ClientCreated{}, err
	}
	return gen.ClientCreated{Client: c, Token: e.Token, ExpiresAt: e.ExpiresAt, AgentUrl: e.AgentURL}, nil
}

// CreateClient adds a pending client and returns its one-time token.
func (s *Server) CreateClient(ctx context.Context, r gen.CreateClientRequestObject) (gen.CreateClientResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, badRequest("missing body")
	}
	e, err := s.d.Agents.CreateClient(ctx, r.OrgId, r.Body.Name, r.Body.SiteId)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	out, err := s.enrolmentOut(ctx, e)
	if err != nil {
		return nil, err
	}
	return gen.CreateClient201JSONResponse(out), nil
}

// UpdateClient renames a client or changes its site.
func (s *Server) UpdateClient(ctx context.Context, r gen.UpdateClientRequestObject) (gen.UpdateClientResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, badRequest("missing body")
	}
	c, err := s.d.Agents.UpdateClient(ctx, r.OrgId, r.Id, r.Body.Name, r.Body.SiteId)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	out, err := s.clientOut(ctx, c)
	if err != nil {
		return nil, err
	}
	return gen.UpdateClient200JSONResponse(out), nil
}

// DeleteClient removes a pending or revoked client.
func (s *Server) DeleteClient(ctx context.Context, r gen.DeleteClientRequestObject) (gen.DeleteClientResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if err := s.d.Agents.DeleteClient(ctx, r.OrgId, r.Id); err != nil {
		return nil, mapAgentErr(err)
	}
	return gen.DeleteClient204Response{}, nil
}

// RevokeClient refuses the client's agent from now on.
func (s *Server) RevokeClient(ctx context.Context, r gen.RevokeClientRequestObject) (gen.RevokeClientResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	c, err := s.d.Agents.RevokeClient(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	out, err := s.clientOut(ctx, c)
	if err != nil {
		return nil, err
	}
	return gen.RevokeClient200JSONResponse(out), nil
}

// ReenrollClient issues a new token and drops the current agent certificate.
func (s *Server) ReenrollClient(ctx context.Context, r gen.ReenrollClientRequestObject) (gen.ReenrollClientResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	e, err := s.d.Agents.ReenrollClient(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	out, err := s.enrolmentOut(ctx, e)
	if err != nil {
		return nil, err
	}
	return gen.ReenrollClient200JSONResponse(out), nil
}
