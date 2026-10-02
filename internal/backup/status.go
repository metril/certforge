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
// attempt produces. Schedule, Directory and NextAt in
// Status below are all derived from the live "backup" settings section
// instead, not persisted here, so a schedule/directory edit is reflected
// immediately rather than only after the next run.
//
// LastScheduledAt (final review fix wave, finding 2) is deliberately kept
// separate from LastSuccessAt: due()/nextRunAt must advance only when the
// *scheduled* job itself succeeds, never when an on-demand download
// (createBackup/cfctl backup) does — RecordOnDemandSuccess moves
// LastSuccessAt (the contract's own "most recent success, of either kind")
// but never LastScheduledAt.
type statusRecord struct {
	LastSuccessAt   *time.Time `json:"lastSuccessAt"`
	LastScheduledAt *time.Time `json:"lastScheduledAt"`
	LastFailureAt   *time.Time `json:"lastFailureAt"`
	LastError       string     `json:"lastError"`
	LastSizeBytes   *int64     `json:"lastSizeBytes"`
	LastFile        string     `json:"lastFile"`
}

// statusPatch is a partial statusRecord write, merged atomically into the
// stored value by Service.mergeStatus (final review fix wave, finding 2):
// every field left nil (the zero value for a pointer) is omitted from the
// JSON entirely (omitempty) and so leaves whatever is already stored for
// it untouched — unlike a full statusRecord round-tripped through
// Get-then-Set, which silently reverts any field a concurrent writer set
// in between this call's own load and save. A field that must be
// explicitly cleared (LastError back to "") is still sent, as a non-nil
// pointer to the zero value: omitempty only skips a nil pointer, not what
// it points to.
type statusPatch struct {
	LastSuccessAt   *time.Time `json:"lastSuccessAt,omitempty"`
	LastScheduledAt *time.Time `json:"lastScheduledAt,omitempty"`
	LastFailureAt   *time.Time `json:"lastFailureAt,omitempty"`
	LastError       *string    `json:"lastError,omitempty"`
	LastSizeBytes   *int64     `json:"lastSizeBytes,omitempty"`
	LastFile        *string    `json:"lastFile,omitempty"`
}

// Status is getBackupStatus's and readyz's own view (Shared contract's
// BackupStatus schema, kept independent of internal/api/gen — same
// convention as kek.RewrapStatus / monitor's own structs).
type Status struct {
	Schedule string
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
		Schedule:      set.Schedule,
		LastSuccessAt: rec.LastSuccessAt,
		LastFailureAt: rec.LastFailureAt,
		LastError:     rec.LastError,
		LastSizeBytes: rec.LastSizeBytes,
		LastFile:      rec.LastFile,
	}
	if set.Schedule != "off" {
		out.Directory = set.Directory
		next := nextRunAt(set.Schedule, rec.LastScheduledAt, s.now())
		out.NextAt = &next
	}
	return out, nil
}

// nextRunAt computes when the next scheduled backup is due (task-12
// brief): lastScheduled plus the schedule's cadence, or now when the
// scheduled job has never succeeded yet. lastScheduled is
// statusRecord.LastScheduledAt (final review fix wave, finding 2) — never
// LastSuccessAt, which an on-demand download also moves and must not be
// able to push this out.
func nextRunAt(schedule string, lastScheduled *time.Time, now time.Time) time.Time {
	if lastScheduled == nil {
		return now
	}
	switch schedule {
	case "weekly":
		return lastScheduled.Add(7 * 24 * time.Hour)
	default: // "daily"
		return lastScheduled.Add(24 * time.Hour)
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

// mergeStatus atomically merges patch into the stored status row (final
// review fix wave, finding 2) instead of a Get-then-Set round trip, so a
// concurrent write to a field patch does not itself touch (RecordOnDemandSuccess
// racing runOnce's own save, or the reverse) is never lost.
func (s *Service) mergeStatus(ctx context.Context, patch statusPatch) error {
	return s.Settings.Merge(ctx, StatusKey, patch)
}
