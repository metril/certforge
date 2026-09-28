package agents

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// Enrolment is a pending client and its one-time token.
type Enrolment struct {
	Client    sqlcgen.Client
	Token     string
	ExpiresAt time.Time
	AgentURL  string
}

func cleanClientName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" || len(n) > 100 {
		return "", invalid("name", "name must be 1 to 100 characters")
	}
	return n, nil
}

func (s *Service) checkSite(ctx context.Context, q *sqlcgen.Queries, orgID uuid.UUID, siteID *uuid.UUID) error {
	if siteID == nil {
		return nil
	}
	if _, err := q.GetSite(ctx, sqlcgen.GetSiteParams{ID: *siteID, OrgID: orgID}); errors.Is(err, pgx.ErrNoRows) {
		return invalid("siteId", "site %s is not in this org", *siteID)
	} else if err != nil {
		return err
	}
	return nil
}

// issueToken replaces the client's unused tokens with a fresh one.
func (s *Service) issueToken(ctx context.Context, q *sqlcgen.Queries, clientID uuid.UUID, st Settings, ca *agentca.CA) (string, time.Time, error) {
	tok, err := agentproto.NewToken(st.AgentURL, agentca.Fingerprint(ca.Cert.Raw))
	if err != nil {
		return "", time.Time{}, err
	}
	exp := s.now().Add(st.TokenTTL()).UTC().Truncate(time.Microsecond)
	actor := ""
	if p, ok := authn.PrincipalFrom(ctx); ok {
		actor = p.ActorID()
	}
	if err := q.DeleteUnusedEnrollmentTokens(ctx, clientID); err != nil {
		return "", time.Time{}, err
	}
	if err := q.InsertEnrollmentToken(ctx, sqlcgen.InsertEnrollmentTokenParams{
		ClientID: clientID, TokenHash: agentproto.TokenHash(tok), ExpiresAt: exp, CreatedBy: actor}); err != nil {
		return "", time.Time{}, err
	}
	return tok, exp, nil
}

// tokenCA returns the CA a new token pins: the oldest trusted one, which
// signs the listener certificate, so a new agent can verify the listener
// during a rotation too.
func (s *Service) tokenCA(ctx context.Context) (*agentca.CA, error) {
	if _, err := s.CA.EnsureActive(ctx); err != nil {
		return nil, err
	}
	return s.CA.Oldest(ctx)
}

// CreateClient adds a pending client with a one-time enrolment token.
func (s *Service) CreateClient(ctx context.Context, orgID uuid.UUID, name string, siteID *uuid.UUID) (Enrolment, error) {
	name, err := cleanClientName(name)
	if err != nil {
		return Enrolment{}, err
	}
	ca, err := s.tokenCA(ctx)
	if err != nil {
		return Enrolment{}, err
	}
	st := s.CurrentSettings(ctx)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Enrolment{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	if err := s.checkSite(ctx, q, orgID, siteID); err != nil {
		return Enrolment{}, err
	}
	c, err := q.CreateClient(ctx, sqlcgen.CreateClientParams{OrgID: orgID, SiteID: siteID, Name: name})
	switch pgCode(err) {
	case pgUniqueViolation:
		return Enrolment{}, conflict("A client named %q exists in this org.", name)
	case pgForeignKeyViolation:
		return Enrolment{}, notFound("org %s", orgID)
	}
	if err != nil {
		return Enrolment{}, err
	}
	tok, exp, err := s.issueToken(ctx, q, c.ID, st, ca)
	if err != nil {
		return Enrolment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Enrolment{}, err
	}
	s.audit(ctx, audit.Event{Action: "client.create", ResourceType: "client", ResourceID: c.ID.String(), OrgID: &orgID,
		Details: map[string]any{"name": c.Name, "siteId": siteID, "tokenExpiresAt": exp}})
	return Enrolment{Client: c, Token: tok, ExpiresAt: exp, AgentURL: st.AgentURL}, nil
}

func (s *Service) lockClient(ctx context.Context, q *sqlcgen.Queries, orgID, id uuid.UUID) (sqlcgen.Client, error) {
	c, err := q.LockClient(ctx, sqlcgen.LockClientParams{ID: id, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return c, notFound("client %s", id)
	}
	return c, err
}

// ReenrollClient returns a client to pending with a fresh token and drops
// its current agent certificate and socket.
func (s *Service) ReenrollClient(ctx context.Context, orgID, id uuid.UUID) (Enrolment, error) {
	ca, err := s.tokenCA(ctx)
	if err != nil {
		return Enrolment{}, err
	}
	st := s.CurrentSettings(ctx)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Enrolment{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	cur, err := s.lockClient(ctx, q, orgID, id)
	if err != nil {
		return Enrolment{}, err
	}
	if cur.Status == "revoked" {
		return Enrolment{}, conflict("Revoked clients cannot re-enrol; create a new client.")
	}
	c, err := q.SetClientPending(ctx, id)
	if err != nil {
		return Enrolment{}, err
	}
	tok, exp, err := s.issueToken(ctx, q, id, st, ca)
	if err != nil {
		return Enrolment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Enrolment{}, err
	}
	if s.Hub != nil {
		s.Hub.Send(id, agentproto.Revoked{})
		s.Hub.Close(id, agentproto.CloseRevoked, "re-enrolled")
	}
	s.audit(ctx, audit.Event{Action: "client.reenroll", ResourceType: "client", ResourceID: id.String(), OrgID: &orgID,
		Details: map[string]any{"previousSerial": cur.AgentCertSerial, "previousStatus": cur.Status, "tokenExpiresAt": exp}})
	return Enrolment{Client: c, Token: tok, ExpiresAt: exp, AgentURL: st.AgentURL}, nil
}

// RevokeClient refuses the client's agent from now on. Idempotent.
func (s *Service) RevokeClient(ctx context.Context, orgID, id uuid.UUID) (sqlcgen.Client, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return sqlcgen.Client{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	cur, err := s.lockClient(ctx, q, orgID, id)
	if err != nil || cur.Status == "revoked" {
		return cur, err
	}
	c, err := q.SetClientRevoked(ctx, id)
	if err != nil {
		return c, err
	}
	if err := q.DeleteUnusedEnrollmentTokens(ctx, id); err != nil {
		return c, err
	}
	// A revoked client's agent can never come back to confirm a removal,
	// so every grant of this client still awaiting one is hard-deleted now
	// rather than left removal-pending forever.
	pending, err := q.RemovalPendingGrantsForClient(ctx, &id)
	if err != nil {
		return c, err
	}
	for _, g := range pending {
		if err := q.DeleteGrantRow(ctx, g.ID); err != nil {
			return c, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return c, err
	}
	if s.Hub != nil {
		s.Hub.Send(id, agentproto.Revoked{})
		s.Hub.Close(id, agentproto.CloseRevoked, "revoked")
	}
	s.audit(ctx, audit.Event{Action: "client.revoke", ResourceType: "client", ResourceID: id.String(), OrgID: &orgID,
		Details: map[string]any{"serial": cur.AgentCertSerial, "previousStatus": cur.Status}})
	for _, g := range pending {
		d := grantDetails(g)
		d["forced"] = true
		s.audit(ctx, audit.Event{Action: "grant.delete", ResourceType: "grant", ResourceID: g.ID.String(), OrgID: &orgID, Details: d})
	}
	return c, nil
}

// UpdateClient renames a client and sets or clears its site.
func (s *Service) UpdateClient(ctx context.Context, orgID, id uuid.UUID, name string, siteID *uuid.UUID) (sqlcgen.Client, error) {
	name, err := cleanClientName(name)
	if err != nil {
		return sqlcgen.Client{}, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return sqlcgen.Client{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	cur, err := s.lockClient(ctx, q, orgID, id)
	if err != nil {
		return cur, err
	}
	if err := s.checkSite(ctx, q, orgID, siteID); err != nil {
		return cur, err
	}
	c, err := q.UpdateClient(ctx, sqlcgen.UpdateClientParams{Name: name, SiteID: siteID, ID: id, OrgID: orgID})
	if pgCode(err) == pgUniqueViolation {
		return cur, conflict("A client named %q exists in this org.", name)
	}
	if err != nil {
		return cur, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cur, err
	}
	s.audit(ctx, audit.Event{Action: "client.update", ResourceType: "client", ResourceID: id.String(), OrgID: &orgID,
		Details: map[string]any{"before": map[string]any{"name": cur.Name, "siteId": cur.SiteID},
			"after": map[string]any{"name": c.Name, "siteId": c.SiteID}}})
	return c, nil
}

// DeleteClient removes a pending or revoked client with its grants.
func (s *Service) DeleteClient(ctx context.Context, orgID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	cur, err := s.lockClient(ctx, q, orgID, id)
	if err != nil {
		return err
	}
	if cur.Status == "active" {
		return conflict("Revoke the client before deleting it.")
	}
	// lockClient already took the client's row FOR UPDATE, which blocks (and
	// is blocked by) any certificate or org-defaults write that first takes
	// a FOR KEY SHARE lock on it (issuance.Store.validateRuleClientTx), so
	// this reference check reads the current, committed truth: nothing can
	// add a new rule referencing id between it and DeleteClient below.
	names, err := q.CertificatesUsingClient(ctx, sqlcgen.CertificatesUsingClientParams{OrgID: orgID, ClientID: id})
	if err != nil {
		return err
	}
	if len(names) > 0 {
		return conflict("This client is used by verification rules on: %s. Change or remove those rules first.", strings.Join(names, ", "))
	}
	if _, err := q.DeleteClient(ctx, sqlcgen.DeleteClientParams{ID: id, OrgID: orgID}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.audit(ctx, audit.Event{Action: "client.delete", ResourceType: "client", ResourceID: id.String(), OrgID: &orgID,
		Details: map[string]any{"name": cur.Name, "status": cur.Status}})
	return nil
}
