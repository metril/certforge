package issuance

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// Attempt outcomes.
const (
	OutcomeRunning = "running"
	OutcomeSuccess = "success"
	OutcomeFailed  = "failed"
)

var _ challenge.ManualStore = (*Store)(nil)

// Attempt is one issuance run.
type Attempt struct {
	ID, CertID    uuid.UUID
	StartedAt     time.Time
	FinishedAt    *time.Time
	Outcome       string
	ACMEErrorType string
	RetryAfter    *time.Time
	Steps         []Step
	Log           string
}

// ManualTXT is a pending manual-dns record as shown to the operator.
type ManualTXT struct {
	Name, Value string
	TTL         int
	ExpiresAt   time.Time
}

// CreateAttempt starts an attempt row.
func (s *Store) CreateAttempt(ctx context.Context, certID uuid.UUID) (uuid.UUID, error) {
	row, err := s.q.CreateAttempt(ctx, certID)
	return row.ID, err
}

// SaveAttemptProgress persists the live timeline.
func (s *Store) SaveAttemptProgress(ctx context.Context, id uuid.UUID, steps []Step, log string) error {
	b, err := json.Marshal(steps)
	if err != nil {
		return err
	}
	return s.q.SaveAttemptProgress(ctx, sqlcgen.SaveAttemptProgressParams{ID: id, Steps: b, Log: log})
}

// FinishAttempt closes an attempt; tx may be nil.
func (s *Store) FinishAttempt(ctx context.Context, tx pgx.Tx, id uuid.UUID, outcome, acmeType string, retryAfter *time.Time, steps []Step, log string) error {
	b, err := json.Marshal(steps)
	if err != nil {
		return err
	}
	q := s.q
	if tx != nil {
		q = q.WithTx(tx)
	}
	return q.FinishAttempt(ctx, sqlcgen.FinishAttemptParams{ID: id, Outcome: outcome, AcmeErrorType: acmeType,
		RetryAfter: retryAfter, Steps: b, Log: log})
}

// FailStaleAttempts closes attempts left running by a crash or timeout.
func (s *Store) FailStaleAttempts(ctx context.Context, olderThan time.Duration) (int64, error) {
	return s.q.FailStaleAttempts(ctx, time.Now().Add(-olderThan))
}

// ListAttempts returns the newest attempts of an org's certificate.
func (s *Store) ListAttempts(ctx context.Context, orgID, certID uuid.UUID, limit int) ([]Attempt, error) {
	if _, err := s.GetCertificate(ctx, orgID, certID); err != nil {
		return nil, err
	}
	rows, err := s.q.ListAttempts(ctx, sqlcgen.ListAttemptsParams{CertID: certID, Limit: int32(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]Attempt, 0, len(rows))
	for _, r := range rows {
		a := Attempt{ID: r.ID, CertID: r.CertID, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Outcome: r.Outcome,
			ACMEErrorType: r.AcmeErrorType, RetryAfter: r.RetryAfter, Log: r.Log}
		if err := json.Unmarshal(r.Steps, &a.Steps); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// ManualPending lists unconfirmed manual-dns records of an org's certificate.
func (s *Store) ManualPending(ctx context.Context, orgID, certID uuid.UUID) ([]ManualTXT, error) {
	if _, err := s.GetCertificate(ctx, orgID, certID); err != nil {
		return nil, err
	}
	rows, err := s.q.ListManualPending(ctx, certID)
	if err != nil {
		return nil, err
	}
	out := make([]ManualTXT, len(rows))
	for i, r := range rows {
		out[i] = ManualTXT{Name: r.Fqdn, Value: r.Value, TTL: int(r.Ttl), ExpiresAt: r.ExpiresAt}
	}
	return out, nil
}

// ConfirmManual marks every unexpired pending record of the certificate as
// confirmed and returns how many were confirmed.
func (s *Store) ConfirmManual(ctx context.Context, orgID, certID uuid.UUID) (int64, error) {
	if _, err := s.GetCertificate(ctx, orgID, certID); err != nil {
		return 0, err
	}
	return s.q.ConfirmManualPending(ctx, certID)
}

// InsertManualPending implements challenge.ManualStore.
func (s *Store) InsertManualPending(ctx context.Context, r challenge.ManualRecord) error {
	return s.q.InsertManualPending(ctx, sqlcgen.InsertManualPendingParams{AttemptID: r.AttemptID, CertID: r.CertID,
		Domain: r.Domain, Fqdn: r.FQDN, Value: r.Value, Ttl: int32(r.TTL), ExpiresAt: r.ExpiresAt})
}

// ManualConfirmed implements challenge.ManualStore.
func (s *Store) ManualConfirmed(ctx context.Context, attemptID uuid.UUID) (bool, error) {
	return s.q.ManualAllConfirmed(ctx, attemptID)
}

// DeleteManualPending implements challenge.ManualStore.
func (s *Store) DeleteManualPending(ctx context.Context, attemptID uuid.UUID) error {
	return s.q.DeleteManualPending(ctx, attemptID)
}
