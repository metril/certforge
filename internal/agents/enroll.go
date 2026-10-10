package agents

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// AuthenticateKey maps a client id and the serial of the certificate it signs
// with (the signed keyid of the agent protocol) to its active client: it must
// exist, be active and hold serial as its newest.
func (s *Service) AuthenticateKey(ctx context.Context, id uuid.UUID, serial string) (sqlcgen.Client, error) {
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
	if c.AgentCertSerial != serial {
		return c, unauthorized("This agent certificate was replaced; use the newest certificate or enrol again.")
	}
	return c, nil
}

// VerifyAgentCert checks that der is an agent client certificate issued by a
// trusted agent CA and unexpired, and returns the client id, certificate
// serial and signing key it proves. It does not check the client's state:
// follow with AuthenticateKey.
func (s *Service) VerifyAgentCert(ctx context.Context, der []byte) (uuid.UUID, string, *ecdsa.PublicKey, error) {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return uuid.Nil, "", nil, unauthorized("This is not a CertForge agent certificate.")
	}
	trusted, err := s.CA.Trusted(ctx)
	if err != nil {
		return uuid.Nil, "", nil, err
	}
	roots := x509.NewCertPool()
	for _, c := range trusted {
		roots.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: s.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return uuid.Nil, "", nil, unauthorized("This agent certificate is not trusted or has expired.")
	}
	id, err := agentca.ClientIDFromCert(leaf)
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if err != nil || !ok || pub.Curve != elliptic.P256() {
		return uuid.Nil, "", nil, unauthorized("This is not a CertForge agent certificate.")
	}
	return id, agentca.SerialHex(leaf), pub, nil
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
