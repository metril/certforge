package backup

import (
	"context"
	"errors"
	"time"

	"github.com/metril/certforge/internal/settings"
)

// StatusKey is the settings-table key the most recent backup attempt's
// outcome is persisted to (Shared contract: readyz's "backup" check and
// getBackupStatus both read this, no extra Postgres query beyond the
// settings read).
const StatusKey = "backup.status"

// statusRecord is StatusKey's persisted shape: only what an actual backup
// attempt produces. Schedule, EscrowConfirmed, Directory and NextAt in
// Status below are all derived from the live "backup" settings section
// instead, not persisted here, so a schedule/directory edit is reflected
// immediately rather than only after the next run.
type statusRecord struct {
	LastSuccessAt *time.Time `json:"lastSuccessAt"`
	LastFailureAt *time.Time `json:"lastFailureAt"`
	LastError     string     `json:"lastError"`
	LastSizeBytes *int64     `json:"lastSizeBytes"`
	LastFile      string     `json:"lastFile"`
}

// Status is getBackupStatus's and readyz's own view (Shared contract's
// BackupStatus schema, kept independent of internal/api/gen — same
// convention as kek.RewrapStatus / monitor's own structs).
type Status struct {
	Schedule        string
	EscrowConfirmed bool
	// Directory is "" while Schedule == "off" (Shared contract: "null
	// while schedule is off").
	Directory     string
	LastSuccessAt *time.Time
	LastFailureAt *time.Time
	// LastError is "" after a success or before any attempt.
	LastError     string
	LastSizeBytes *int64
	// LastFile is "" for an on-demand download or before any scheduled
	// backup (Shared contract).
	LastFile string
	// NextAt is nil while Schedule == "off".
	NextAt *time.Time
}

// Status reports the live "backup" settings section plus the most recent
// attempt's outcome (no extra Postgres query beyond the settings read and
// the StatusKey settings read — Shared contract's readiness row).
func (s *Service) Status(ctx context.Context) (Status, error) {
	set, err := s.settings(ctx)
	if err != nil {
		return Status{}, err
	}
	rec, err := s.loadStatus(ctx)
	if err != nil {
		return Status{}, err
	}
	out := Status{
		Schedule:        set.Schedule,
		EscrowConfirmed: set.KEKEscrowConfirmed,
		LastSuccessAt:   rec.LastSuccessAt,
		LastFailureAt:   rec.LastFailureAt,
		LastError:       rec.LastError,
		LastSizeBytes:   rec.LastSizeBytes,
		LastFile:        rec.LastFile,
	}
	if set.Schedule != "off" {
		out.Directory = set.Directory
		next := nextRunAt(set.Schedule, rec.LastSuccessAt, s.now())
		out.NextAt = &next
	}
	return out, nil
}

// nextRunAt computes when the next scheduled backup is due (task-12
// brief): lastSuccess plus the schedule's cadence, or now when there has
// been no success yet.
func nextRunAt(schedule string, lastSuccess *time.Time, now time.Time) time.Time {
	if lastSuccess == nil {
		return now
	}
	switch schedule {
	case "weekly":
		return lastSuccess.Add(7 * 24 * time.Hour)
	default: // "daily"
		return lastSuccess.Add(24 * time.Hour)
	}
}

// loadStatus reads the most recent backup attempt's outcome, the zero
// value if none has ever run.
func (s *Service) loadStatus(ctx context.Context) (statusRecord, error) {
	var rec statusRecord
	err := s.Settings.Get(ctx, StatusKey, &rec)
	if errors.Is(err, settings.ErrNotFound) {
		return statusRecord{}, nil
	}
	if err != nil {
		return statusRecord{}, err
	}
	return rec, nil
}

func (s *Service) saveStatus(ctx context.Context, rec statusRecord) error {
	return s.Settings.Set(ctx, StatusKey, rec)
}
