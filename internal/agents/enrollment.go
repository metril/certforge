package agents

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// MaxPendingEnrollments caps the requests waiting for approval in one org, so
// a leaked token cannot fill the approval queue (each token is single use,
// but an attacker holding many could).
const MaxPendingEnrollments = 50

// pruneAfter is how long a finished request row is kept.
const pruneAfter = 7 * 24 * time.Hour

// EnrollToken is an enrolment token found by its lookup id. Hash keys the
// proof of possession; it never leaves the server.
type EnrollToken struct {
	ID, ClientID uuid.UUID
	Hash         []byte
}

// PendingApproval is the event raised when a request starts waiting.
type PendingApproval struct {
	OrgID      uuid.UUID
	ClientID   uuid.UUID
	ClientName string
	RequestID  uuid.UUID
	VerifyCode string
	Hostname   string
	ExpiresAt  time.Time
}

// EnrollTokenByLookup finds a redeemable token. Unknown, expired and (unless
// a resubmission of the same CSR follows) used tokens all read the same.
func (s *Service) EnrollTokenByLookup(ctx context.Context, lookup []byte) (EnrollToken, error) {
	t, err := s.Q.GetEnrollmentTokenByLookup(ctx, lookup)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnrollToken{}, unauthorized(badToken)
	}
	if err != nil {
		return EnrollToken{}, err
	}
	return EnrollToken{ID: t.ID, ClientID: t.ClientID, Hash: t.TokenHash}, nil
}

func newPollSecret() (secret string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, err
	}
	h := sha256.Sum256([]byte(base64.RawURLEncoding.EncodeToString(b)))
	return base64.RawURLEncoding.EncodeToString(b), h[:], nil
}

func hashPollSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// SubmitEnrollment redeems tok for csrPEM (whose proof of possession the
// caller has verified). The token is consumed, and a request is recorded: it
// waits for an administrator, or is approved at once when approval is off.
// Presenting the same CSR again for a token whose request is still open
// issues a fresh poll secret (the reply may have been lost); any other key
// is refused.
func (s *Service) SubmitEnrollment(ctx context.Context, tok EnrollToken, csrPEM string, facts agentproto.Facts, sourceIP string) (agentproto.EnrollAccepted, error) {
	csr, err := agentca.ParseCSR([]byte(csrPEM))
	if err != nil {
		return agentproto.EnrollAccepted{}, invalid("csr", "%v", err)
	}
	oldest, err := s.CA.Oldest(ctx)
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	caFP := agentca.Fingerprint(oldest.Cert.Raw)
	pubFP := agentproto.CertFingerprint(csr.RawSubjectPublicKeyInfo)
	code := agentproto.VerifyCode(csr.RawSubjectPublicKeyInfo, caFP)
	st := s.CurrentSettings(ctx)
	now := s.now().UTC().Truncate(time.Microsecond)
	secret, secretHash, err := newPollSecret()
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	factsJSON, _ := json.Marshal(agentproto.Facts{Hostname: clip(facts.Hostname, 253), OS: clip(facts.OS, 32),
		Arch: clip(facts.Arch, 32), AgentVersion: clip(facts.AgentVersion, 64)})

	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	if _, err := q.ExpireEnrollmentRequests(ctx, now); err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	if _, err := q.PruneEnrollmentRequests(ctx, now.Add(-pruneAfter)); err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	clientID, err := q.ConsumeEnrollmentTokenByID(ctx, tok.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.resubmit(ctx, tx, q, tok, pubFP, secret, secretHash, now)
	}
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	cur, err := q.LockClientByID(ctx, clientID)
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	if cur.Status != "pending" {
		return agentproto.EnrollAccepted{}, conflict("This client is %s; re-enrol it for a new token.", cur.Status)
	}
	status := "approved"
	if st.ApprovalRequired() {
		status = "pending"
		n, err := q.CountPendingEnrollmentRequests(ctx, sqlcgen.CountPendingEnrollmentRequestsParams{OrgID: cur.OrgID, ExpiresAt: now})
		if err != nil {
			return agentproto.EnrollAccepted{}, err
		}
		if n >= MaxPendingEnrollments {
			return agentproto.EnrollAccepted{}, conflict("Too many enrolment requests are waiting for approval; approve or reject some first.")
		}
	}
	req, err := q.InsertEnrollmentRequest(ctx, sqlcgen.InsertEnrollmentRequestParams{OrgID: cur.OrgID, ClientID: cur.ID, TokenID: tok.ID,
		PollSecretHash: secretHash, Csr: csrPEM, PubkeyFp: pubFP, VerifyCode: code, Facts: factsJSON, SourceIp: clip(sourceIP, 64),
		Status: status, ExpiresAt: now.Add(st.PendingTTL())})
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	actx := authn.WithPrincipal(ctx, AgentPrincipal(cur))
	s.audit(actx, audit.Event{Action: "client.enrol_requested", ResourceType: "client", ResourceID: cur.ID.String(), OrgID: &cur.OrgID,
		Details: map[string]any{"requestId": req.ID, "verifyCode": code, "hostname": clip(facts.Hostname, 253), "approvalRequired": status == "pending",
			"expiresAt": req.ExpiresAt}})
	if status == "pending" && s.OnPendingApproval != nil {
		s.OnPendingApproval(ctx, PendingApproval{OrgID: cur.OrgID, ClientID: cur.ID, ClientName: cur.Name, RequestID: req.ID,
			VerifyCode: code, Hostname: clip(facts.Hostname, 253), ExpiresAt: req.ExpiresAt})
	}
	return agentproto.EnrollAccepted{ID: req.ID, PollSecret: secret, VerifyCode: code, Status: status, ExpiresAt: req.ExpiresAt}, nil
}

// resubmit answers a used token: only its own, still open request with the
// same key gets a (new) poll secret.
func (s *Service) resubmit(ctx context.Context, tx pgx.Tx, q *sqlcgen.Queries, tok EnrollToken, pubFP, secret string, secretHash []byte, now time.Time) (agentproto.EnrollAccepted, error) {
	req, err := q.GetEnrollmentRequestByTokenForUpdate(ctx, tok.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return agentproto.EnrollAccepted{}, unauthorized(badToken)
	}
	if err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	if req.PubkeyFp != pubFP || (req.Status != "pending" && req.Status != "approved") || !now.Before(req.ExpiresAt) {
		return agentproto.EnrollAccepted{}, unauthorized(badToken)
	}
	if err := q.RotateEnrollmentPollSecret(ctx, sqlcgen.RotateEnrollmentPollSecretParams{ID: req.ID, PollSecretHash: secretHash}); err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return agentproto.EnrollAccepted{}, err
	}
	return agentproto.EnrollAccepted{ID: req.ID, PollSecret: secret, VerifyCode: req.VerifyCode, Status: req.Status, ExpiresAt: req.ExpiresAt}, nil
}

// EnrollmentKey is the public key of the CSR behind a request: the key that
// must sign its polls.
func (s *Service) EnrollmentKey(ctx context.Context, id uuid.UUID) (*ecdsa.PublicKey, error) {
	req, err := s.Q.GetEnrollmentRequest(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, unauthorized("Unknown enrolment request.")
	}
	if err != nil {
		return nil, err
	}
	csr, err := agentca.ParseCSR([]byte(req.Csr))
	if err != nil {
		return nil, err
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, unauthorized("Unknown enrolment request.")
	}
	return pub, nil
}

// PollEnrollment reports where a request stands. The first poll after
// approval signs and records the certificate and activates the client; later
// polls repeat it until the collection window closes. The caller has
// verified that the poll is signed by the CSR key.
func (s *Service) PollEnrollment(ctx context.Context, id uuid.UUID, pollSecret string) (agentproto.EnrollPoll, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return agentproto.EnrollPoll{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	req, err := q.LockEnrollmentRequest(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return agentproto.EnrollPoll{}, unauthorized("Unknown enrolment request.")
	}
	if err != nil {
		return agentproto.EnrollPoll{}, err
	}
	if subtle.ConstantTimeCompare(hashPollSecret(pollSecret), req.PollSecretHash) != 1 {
		return agentproto.EnrollPoll{}, unauthorized("The poll secret is wrong.")
	}
	out := agentproto.EnrollPoll{Status: req.Status, ExpiresAt: req.ExpiresAt}
	live := now.Before(req.ExpiresAt)
	switch req.Status {
	case "rejected", "expired":
		return out, nil
	case "pending", "approved", "issued":
		if !live {
			if req.Status != "issued" {
				if err := q.SetEnrollmentRequestStatus(ctx, sqlcgen.SetEnrollmentRequestStatusParams{ID: id, Status: "expired"}); err != nil {
					return out, err
				}
				if err := tx.Commit(ctx); err != nil {
					return out, err
				}
			}
			out.Status = agentproto.EnrollExpired
			return out, nil
		}
	}
	if req.Status == "pending" {
		return out, nil
	}
	st := s.CurrentSettings(ctx)
	if req.Status == "issued" {
		trusted, err := s.CA.WithQueries(q).Trusted(ctx)
		if err != nil {
			return out, err
		}
		out.Status = agentproto.EnrollApproved
		out.Certificate, out.TrustBundle = *req.CertificatePem, string(agentca.BundlePEM(trusted))
		out.AgentURL, out.ClientID = st.AgentURL, req.ClientID
		return out, nil
	}
	csr, err := agentca.ParseCSR([]byte(req.Csr))
	if err != nil {
		return out, err
	}
	cur, err := q.LockClientByID(ctx, req.ClientID)
	if err != nil {
		return out, err
	}
	if cur.Status != "pending" {
		return out, conflict("This client is %s; re-enrol it for a new token.", cur.Status)
	}
	ca, err := s.CA.WithQueries(q).Active(ctx)
	if err != nil {
		return out, err
	}
	cert, err := agentca.SignClient(ca, csr, cur.ID, st.AgentCertLifetime(), s.now())
	if err != nil {
		return out, err
	}
	// Re-check under a row lock, in this transaction, that ca is still
	// trusted: see lockSigningCA.
	if err := lockSigningCA(ctx, q, ca.ID); err != nil {
		return out, err
	}
	var facts agentproto.Facts
	_ = json.Unmarshal(req.Facts, &facts)
	c, err := q.ActivateClient(ctx, sqlcgen.ActivateClientParams{ID: cur.ID, AgentCertSerial: agentca.SerialHex(cert),
		AgentCertNotAfter: &cert.NotAfter, AgentCaID: &ca.ID, Hostname: facts.Hostname, Os: facts.OS, Arch: facts.Arch,
		AgentVersion: facts.AgentVersion})
	if err != nil {
		return out, err
	}
	certPEM := string(agentca.CertPEM(cert.Raw))
	if err := q.MarkEnrollmentIssued(ctx, sqlcgen.MarkEnrollmentIssuedParams{ID: id, CertificatePem: &certPEM}); err != nil {
		return out, err
	}
	trusted, err := s.CA.WithQueries(q).Trusted(ctx)
	if err != nil {
		return out, err
	}
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	s.audit(authn.WithPrincipal(ctx, AgentPrincipal(c)), audit.Event{Action: "client.enrolled", ResourceType: "client",
		ResourceID: c.ID.String(), OrgID: &c.OrgID, Details: map[string]any{"serial": c.AgentCertSerial, "hostname": c.Hostname,
			"agentVersion": c.AgentVersion, "notAfter": cert.NotAfter, "requestId": id, "approvedBy": req.DecidedBy}})
	out.Status = agentproto.EnrollApproved
	out.Certificate, out.TrustBundle = certPEM, string(agentca.BundlePEM(trusted))
	out.AgentURL, out.ClientID = st.AgentURL, c.ID
	return out, nil
}

// PendingEnrollment is a request waiting for an administrator.
type PendingEnrollment struct {
	ID, OrgID, ClientID uuid.UUID
	ClientName          string
	SiteID              *uuid.UUID
	VerifyCode          string
	PubkeyFingerprint   string
	Facts               agentproto.Facts
	SourceIP            string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

// ListPendingEnrollments lists the unexpired requests waiting in orgIDs,
// oldest first.
func (s *Service) ListPendingEnrollments(ctx context.Context, orgIDs []uuid.UUID) ([]PendingEnrollment, error) {
	rows, err := s.Q.ListPendingEnrollmentRequests(ctx, sqlcgen.ListPendingEnrollmentRequestsParams{OrgIds: orgIDs, Now: s.now().UTC()})
	if err != nil {
		return nil, err
	}
	out := make([]PendingEnrollment, 0, len(rows))
	for _, r := range rows {
		p := PendingEnrollment{ID: r.ID, OrgID: r.OrgID, ClientID: r.ClientID, ClientName: r.ClientName, SiteID: r.SiteID,
			VerifyCode: r.VerifyCode, PubkeyFingerprint: r.PubkeyFp, SourceIP: r.SourceIp, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}
		_ = json.Unmarshal(r.Facts, &p.Facts)
		out = append(out, p)
	}
	return out, nil
}

func (s *Service) decide(ctx context.Context, orgID, id uuid.UUID, status, action string) error {
	now := s.now().UTC().Truncate(time.Microsecond)
	actor := ""
	if p, ok := authn.PrincipalFrom(ctx); ok {
		actor = p.ActorID()
	}
	req, err := s.Q.DecideEnrollmentRequest(ctx, sqlcgen.DecideEnrollmentRequestParams{ID: id, OrgID: orgID, Status: status,
		DecidedBy: actor, Now: now, ExpiresAt: now.Add(s.CurrentSettings(ctx).PendingTTL())})
	if errors.Is(err, pgx.ErrNoRows) {
		if _, gerr := s.Q.GetEnrollmentRequest(ctx, id); gerr == nil {
			return conflict("This enrolment request was already decided or has expired.")
		}
		return notFound("enrolment request %s", id)
	}
	if err != nil {
		return err
	}
	var facts agentproto.Facts
	_ = json.Unmarshal(req.Facts, &facts)
	s.audit(ctx, audit.Event{Action: action, ResourceType: "client", ResourceID: req.ClientID.String(), OrgID: &orgID,
		Details: map[string]any{"requestId": id, "verifyCode": req.VerifyCode, "hostname": facts.Hostname}})
	return nil
}

// ApproveEnrollment lets the waiting agent collect its certificate.
func (s *Service) ApproveEnrollment(ctx context.Context, orgID, id uuid.UUID) error {
	return s.decide(ctx, orgID, id, "approved", "client.enrol_approved")
}

// RejectEnrollment refuses a waiting request. The token stays used: re-enrol
// the client for a new one.
func (s *Service) RejectEnrollment(ctx context.Context, orgID, id uuid.UUID) error {
	return s.decide(ctx, orgID, id, "rejected", "client.enrol_rejected")
}
