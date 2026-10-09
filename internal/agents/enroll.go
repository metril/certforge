package agents

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

const badToken = "The enrolment token is invalid, already used or expired."

// AgentPrincipal is the request principal for an authenticated agent;
// audit events recorded under it get actor_type agent and the client id.
func AgentPrincipal(c sqlcgen.Client) authn.Principal {
	return authn.Principal{Kind: authn.KindAgent, ClientID: c.ID, OrgID: c.OrgID,
		Roles: []string{}, Bindings: []authn.Binding{}, OrgIDs: []uuid.UUID{}}
}

// clip makes agent-supplied text safe for a Postgres text column (valid
// UTF-8, no NUL) and cuts it to at most n bytes on a rune boundary.
func clip(s string, n int) string {
	s = strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// lockSigningCA re-reads a CA's status under a shared row lock, inside the
// caller's transaction, and refuses a CA that was retired since it was read
// outside the transaction. Without this, a concurrent agentca.Store.Retire
// (which takes an exclusive row lock) could retire the CA after this
// transaction signed with it but before it committed the client's
// agent_ca_id, stranding the client on a CA nothing trusts. The lock is
// shared (FOR SHARE), not exclusive, so concurrent enrolments and renewals
// against the same CA do not serialize on each other; they still conflict
// with Retire's FOR UPDATE.
func lockSigningCA(ctx context.Context, q *sqlcgen.Queries, id uuid.UUID) error {
	row, err := q.ShareAgentCA(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return conflict("The signing agent CA no longer exists; retry enrolment.")
	}
	if err != nil {
		return err
	}
	if row.Status == "retired" {
		return conflict("The signing agent CA was retired while this request was in flight; retry enrolment.")
	}
	return nil
}

// Enroll consumes a token atomically and signs the agent's first certificate.
func (s *Service) Enroll(ctx context.Context, req agentproto.EnrollRequest) (agentproto.EnrollResponse, error) {
	tok, err := agentproto.ParseToken(req.Token)
	if err != nil {
		return agentproto.EnrollResponse{}, unauthorized(badToken)
	}
	// The pin check reads certificates only; the active CA's key is
	// decrypted below, after the token is consumed, so a bad token never
	// reaches CA material.
	trusted, err := s.CA.Trusted(ctx)
	if err != nil {
		return agentproto.EnrollResponse{}, err
	}
	if len(trusted) == 0 {
		return agentproto.EnrollResponse{}, agentca.ErrNoActive
	}
	if tok.CAFingerprint != agentca.Fingerprint(trusted[0].Raw) {
		return agentproto.EnrollResponse{}, conflict("This token pins an agent CA that no longer signs the listener certificate; re-enrol the client for a new token.")
	}
	csr, err := agentca.ParseCSR([]byte(req.CSR))
	if err != nil {
		return agentproto.EnrollResponse{}, invalid("csr", "%v", err)
	}
	st := s.CurrentSettings(ctx)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return agentproto.EnrollResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	clientID, err := q.ConsumeEnrollmentToken(ctx, agentproto.TokenHash(req.Token))
	if errors.Is(err, pgx.ErrNoRows) {
		return agentproto.EnrollResponse{}, unauthorized(badToken)
	}
	if err != nil {
		return agentproto.EnrollResponse{}, err
	}
	cur, err := q.LockClientByID(ctx, clientID)
	if err != nil {
		return agentproto.EnrollResponse{}, err
	}
	if cur.Status != "pending" {
		return agentproto.EnrollResponse{}, conflict("This client is %s; re-enrol it for a new token.", cur.Status)
	}
	ca, err := s.CA.WithQueries(q).Active(ctx)
	if err != nil {
		return agentproto.EnrollResponse{}, err
	}
	cert, err := agentca.SignClient(ca, csr, clientID, st.AgentCertLifetime(), s.now())
	if err != nil {
		return agentproto.EnrollResponse{}, err
	}
	// Re-check under a row lock, in this transaction, that ca is still
	// trusted: see lockSigningCA.
	if err := lockSigningCA(ctx, q, ca.ID); err != nil {
		return agentproto.EnrollResponse{}, err
	}
	c, err := q.ActivateClient(ctx, sqlcgen.ActivateClientParams{ID: clientID, AgentCertSerial: agentca.SerialHex(cert),
		AgentCertNotAfter: &cert.NotAfter, AgentCaID: &ca.ID, Hostname: clip(req.Facts.Hostname, 253),
		Os: clip(req.Facts.OS, 32), Arch: clip(req.Facts.Arch, 32), AgentVersion: clip(req.Facts.AgentVersion, 64)})
	if err != nil {
		return agentproto.EnrollResponse{}, err
	}
	trusted, err = s.CA.WithQueries(q).Trusted(ctx)
	if err != nil {
		return agentproto.EnrollResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return agentproto.EnrollResponse{}, err
	}
	s.audit(authn.WithPrincipal(ctx, AgentPrincipal(c)), audit.Event{Action: "client.enrolled", ResourceType: "client",
		ResourceID: c.ID.String(), OrgID: &c.OrgID, Details: map[string]any{"serial": c.AgentCertSerial,
			"hostname": c.Hostname, "agentVersion": c.AgentVersion, "notAfter": cert.NotAfter}})
	return agentproto.EnrollResponse{Certificate: string(agentca.CertPEM(cert.Raw)), TrustBundle: string(agentca.BundlePEM(trusted)),
		AgentURL: st.AgentURL, ClientID: c.ID}, nil
}

// Authenticate maps a verified client certificate to its active client and
// refuses any certificate but the newest one issued to it.
func (s *Service) Authenticate(ctx context.Context, leaf *x509.Certificate) (sqlcgen.Client, error) {
	id, err := agentca.ClientIDFromCert(leaf)
	if err != nil {
		return sqlcgen.Client{}, unauthorized("This is not a CertForge agent certificate.")
	}
	c, err := s.Q.GetClientByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, unauthorized("This client no longer exists.")
	}
	if err != nil {
		return c, err
	}
	if c.Status != "active" {
		return c, unauthorized("This client is %s; enrol the agent again with a new token.", c.Status)
	}
	if c.AgentCertSerial != agentca.SerialHex(leaf) {
		return c, unauthorized("This agent certificate was replaced; use the newest certificate or enrol again.")
	}
	return c, nil
}

// Renew signs a fresh certificate for an authenticated agent.
func (s *Service) Renew(ctx context.Context, c sqlcgen.Client, csrPEM string) (agentproto.RenewResponse, error) {
	csr, err := agentca.ParseCSR([]byte(csrPEM))
	if err != nil {
		return agentproto.RenewResponse{}, invalid("csr", "%v", err)
	}
	ca, err := s.CA.Active(ctx)
	if err != nil {
		return agentproto.RenewResponse{}, err
	}
	st := s.CurrentSettings(ctx)
	cert, err := agentca.SignClient(ca, csr, c.ID, st.AgentCertLifetime(), s.now())
	if err != nil {
		return agentproto.RenewResponse{}, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return agentproto.RenewResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	// Re-check under a row lock, in this transaction, that ca is still
	// trusted: see lockSigningCA.
	if err := lockSigningCA(ctx, q, ca.ID); err != nil {
		return agentproto.RenewResponse{}, err
	}
	nc, err := q.RenewClientCert(ctx, sqlcgen.RenewClientCertParams{ID: c.ID, OldSerial: c.AgentCertSerial,
		AgentCertSerial: agentca.SerialHex(cert), AgentCertNotAfter: &cert.NotAfter, AgentCaID: &ca.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		return agentproto.RenewResponse{}, unauthorized("This agent certificate was replaced or revoked.")
	}
	if err != nil {
		return agentproto.RenewResponse{}, err
	}
	trusted, err := s.CA.WithQueries(q).Trusted(ctx)
	if err != nil {
		return agentproto.RenewResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return agentproto.RenewResponse{}, err
	}
	s.audit(ctx, audit.Event{Action: "client.cert_renewed", ResourceType: "client", ResourceID: c.ID.String(), OrgID: &c.OrgID,
		Details: map[string]any{"previousSerial": c.AgentCertSerial, "serial": nc.AgentCertSerial, "notAfter": cert.NotAfter, "caId": ca.ID}})
	return agentproto.RenewResponse{Certificate: string(agentca.CertPEM(cert.Raw)), TrustBundle: string(agentca.BundlePEM(trusted))}, nil
}
