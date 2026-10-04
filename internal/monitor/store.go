package monitor

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

// Store wraps direct Postgres access for external_monitors, the way
// notify.Store and certstore.Store wrap their own tables; Store does not
// itself validate an Input (that is ValidateInput plus, for
// expectedCertificateId, Store.CertificateName; both the API layer's job).
type Store struct {
	Pool *pgxpool.Pool
	Q    *sqlcgen.Queries
}

func fromRow(r sqlcgen.ExternalMonitor) Monitor {
	return Monitor{
		ID: r.ID, OrgID: r.OrgID, Name: r.Name, Host: r.Host, Port: int(r.Port), SNI: r.Sni,
		IntervalSeconds: int(r.IntervalSeconds), ExpectedCertID: r.ExpectedCertID, Enabled: r.Enabled,
		State: r.State, StateChangedAt: r.StateChangedAt, LastCheckedAt: r.LastCheckedAt, NextCheckAt: r.NextCheckAt,
		LastFingerprint: r.LastFingerprint, LastNotAfter: r.LastNotAfter, LastIssuer: r.LastIssuer, LastError: r.LastError,
		ConsecutiveFailures: int(r.ConsecutiveFailures), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func fromGetRow(r sqlcgen.GetMonitorRow) Monitor {
	m := fromRow(sqlcgen.ExternalMonitor{
		ID: r.ID, OrgID: r.OrgID, Name: r.Name, Host: r.Host, Port: r.Port, Sni: r.Sni,
		IntervalSeconds: r.IntervalSeconds, ExpectedCertID: r.ExpectedCertID, Enabled: r.Enabled,
		State: r.State, StateChangedAt: r.StateChangedAt, LastCheckedAt: r.LastCheckedAt, NextCheckAt: r.NextCheckAt,
		LastFingerprint: r.LastFingerprint, LastNotAfter: r.LastNotAfter, LastIssuer: r.LastIssuer, LastError: r.LastError,
		ConsecutiveFailures: r.ConsecutiveFailures, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
	m.ExpectedCertificateName = r.ExpectedCertificateName
	return m
}

func fromListRow(r sqlcgen.ListMonitorsRow) Monitor {
	return fromGetRow(sqlcgen.GetMonitorRow(r))
}

// notFoundErr maps pgx.ErrNoRows to ErrNotFound.
func notFoundErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// List returns orgID's monitors, name ascending.
func (s *Store) List(ctx context.Context, orgID uuid.UUID) ([]Monitor, error) {
	rows, err := s.Q.ListMonitors(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]Monitor, len(rows))
	for i, r := range rows {
		out[i] = fromListRow(r)
	}
	return out, nil
}

// Get returns one monitor of orgID.
func (s *Store) Get(ctx context.Context, orgID, id uuid.UUID) (Monitor, error) {
	r, err := s.Q.GetMonitor(ctx, sqlcgen.GetMonitorParams{ID: id, OrgID: orgID})
	if err != nil {
		return Monitor{}, notFoundErr(err)
	}
	return fromGetRow(r), nil
}

// GetByID returns one monitor by id alone (Shared contract: Service.Check
// takes no orgID), with its expected certificate's name resolved
// separately since GetMonitorByID has no org to join against.
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (Monitor, error) {
	r, err := s.Q.GetMonitorByID(ctx, id)
	if err != nil {
		return Monitor{}, notFoundErr(err)
	}
	m := fromRow(r)
	if m.ExpectedCertID != nil {
		if name, err := s.CertificateName(ctx, m.OrgID, *m.ExpectedCertID); err == nil {
			m.ExpectedCertificateName = &name
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return Monitor{}, err
		}
	}
	return m, nil
}

// Count returns how many monitors orgID already has (createMonitor's
// per-org limit).
func (s *Store) Count(ctx context.Context, orgID uuid.UUID) (int, error) {
	n, err := s.Q.CountMonitorsInOrg(ctx, orgID)
	return int(n), err
}

// CertificateName validates that certID is a certificate of orgID and
// returns its name (Shared contract: "a certificate in another org is
// 422"); pgx.ErrNoRows means it is not.
func (s *Store) CertificateName(ctx context.Context, orgID, certID uuid.UUID) (string, error) {
	return s.Q.CertificateNameInOrg(ctx, sqlcgen.CertificateNameInOrgParams{ID: certID, OrgID: orgID})
}

// CertificateFingerprint returns certID's current version's leaf
// fingerprint (hex SHA-256, the same as certstore); pgx.ErrNoRows means the
// certificate has no current version.
func (s *Store) CertificateFingerprint(ctx context.Context, certID uuid.UUID) (string, error) {
	return s.Q.CertificateCurrentFingerprint(ctx, certID)
}

// FingerprintKnownInOrg reports whether fp is some certificate's current
// version in orgID (batch-3 review finding 1: an unset expectedCertificateId
// checks the observed leaf against the org as a whole, not against nothing).
func (s *Store) FingerprintKnownInOrg(ctx context.Context, orgID uuid.UUID, fp string) (bool, error) {
	return s.Q.MonitorFingerprintKnownInOrg(ctx, sqlcgen.MonitorFingerprintKnownInOrgParams{OrgID: orgID, Sha256Fp: fp})
}

// Create stores a new monitor. A unique-violation on (org_id, name) or a
// foreign-key violation on org_id is left to the caller (api.pgCode), the
// same convention channels.go/delivery.go use.
func (s *Store) Create(ctx context.Context, orgID uuid.UUID, in Input) (Monitor, error) {
	return s.create(ctx, s.Q, orgID, in)
}

// CreateCapped is Create under the per-org cap (S13): the org row is locked
// FOR UPDATE in one transaction around the count and the insert, so
// concurrent creates cannot go past max. ErrOverCap when the org is full;
// pgx.ErrNoRows when the org does not exist.
func (s *Store) CreateCapped(ctx context.Context, orgID uuid.UUID, in Input, max int) (Monitor, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Monitor{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	if _, err := q.LockOrg(ctx, orgID); err != nil {
		return Monitor{}, err
	}
	n, err := q.CountMonitorsInOrg(ctx, orgID)
	if err != nil {
		return Monitor{}, err
	}
	if int(n) >= max {
		return Monitor{}, ErrOverCap
	}
	m, err := s.create(ctx, q, orgID, in)
	if err != nil {
		return Monitor{}, err
	}
	return m, tx.Commit(ctx)
}

func (s *Store) create(ctx context.Context, q *sqlcgen.Queries, orgID uuid.UUID, in Input) (Monitor, error) {
	r, err := q.CreateMonitor(ctx, sqlcgen.CreateMonitorParams{
		OrgID: orgID, Name: in.Name, Host: in.Host, Port: int32(in.Port), Sni: in.SNI,
		IntervalSeconds: int32(in.IntervalSeconds), ExpectedCertID: in.ExpectedCertID, Enabled: in.Enabled,
	})
	if err != nil {
		return Monitor{}, err
	}
	m := fromRow(r)
	if m.ExpectedCertID != nil {
		if name, err := q.CertificateNameInOrg(ctx, sqlcgen.CertificateNameInOrgParams{ID: *m.ExpectedCertID, OrgID: orgID}); err == nil {
			m.ExpectedCertificateName = &name
		}
	}
	return m, nil
}

// Update replaces a monitor's fields. resetState is the caller's own
// ResetsState(cur, in) decision (Shared contract, updateMonitor): true sets
// state back to unknown and nextCheckAt to now; false leaves state,
// state_changed_at and next_check_at exactly as they are in the database at
// write time — a SQL CASE (UpdateMonitor), not a value read earlier and
// passed back in, so a concurrent check's own CAS transition
// (TransitionState) landing between the caller's read and this write is
// never silently reverted (batch-3 review finding 4).
func (s *Store) Update(ctx context.Context, orgID, id uuid.UUID, in Input, resetState bool) (Monitor, error) {
	r, err := s.Q.UpdateMonitor(ctx, sqlcgen.UpdateMonitorParams{
		ID: id, OrgID: orgID, Name: in.Name, Host: in.Host, Port: int32(in.Port), Sni: in.SNI,
		IntervalSeconds: int32(in.IntervalSeconds), ExpectedCertID: in.ExpectedCertID, Enabled: in.Enabled,
		ResetState: resetState,
	})
	if err != nil {
		return Monitor{}, notFoundErr(err)
	}
	m := fromRow(r)
	if m.ExpectedCertID != nil {
		if name, err := s.CertificateName(ctx, orgID, *m.ExpectedCertID); err == nil {
			m.ExpectedCertificateName = &name
		}
	}
	return m, nil
}

// Delete removes a monitor of orgID.
func (s *Store) Delete(ctx context.Context, orgID, id uuid.UUID) error {
	n, err := s.Q.DeleteMonitor(ctx, sqlcgen.DeleteMonitorParams{ID: id, OrgID: orgID})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DueIDs returns up to limit enabled monitors whose next check is due.
func (s *Store) DueIDs(ctx context.Context, limit int) ([]uuid.UUID, error) {
	return s.Q.DueMonitorIDs(ctx, int32(limit))
}

// TransitionParams is TransitionState's own argument bundle, kept as one
// struct rather than nine positional params.
type TransitionParams struct {
	ID                        uuid.UUID
	OldState, NewState        string
	StateChangedAt, CheckedAt time.Time
	NextCheckAt               time.Time
	LastFingerprint           string
	LastNotAfter              *time.Time
	LastIssuer, LastError     string
	ConsecutiveFailures       int
	// OldFailures is the counter the caller read; the CAS applies only while it still holds.
	OldFailures int
}

// TransitionState is the R5 compare-and-set: it applies only while the row
// still has OldState (WHERE id AND state), reporting whether it did
// (false: a concurrent check already moved the row on, and this call wrote
// nothing).
func (s *Store) TransitionState(ctx context.Context, p TransitionParams) (bool, error) {
	return s.TransitionStateWith(ctx, p, nil)
}

// TransitionStateWith is TransitionState inside one transaction: when the
// compare-and-set wins, onWin (if non-nil) runs with that transaction, and an
// error from it rolls the transition back — a state change and its event
// commit together or not at all.
func (s *Store) TransitionStateWith(ctx context.Context, p TransitionParams, onWin func(tx pgx.Tx) error) (bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	n, err := s.Q.WithTx(tx).TransitionMonitorState(ctx, sqlcgen.TransitionMonitorStateParams{
		ID: p.ID, OldState: p.OldState, State: p.NewState, StateChangedAt: p.StateChangedAt,
		LastCheckedAt: &p.CheckedAt, NextCheckAt: p.NextCheckAt, LastFingerprint: p.LastFingerprint,
		LastNotAfter: p.LastNotAfter, LastIssuer: p.LastIssuer, LastError: p.LastError,
		ConsecutiveFailures: int32(p.ConsecutiveFailures), OldFailures: int32(p.OldFailures),
	})
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if onWin != nil {
		if err := onWin(tx); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}
