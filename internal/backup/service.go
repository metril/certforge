package backup

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/settings"
)

// SectionName is the "backup" global settings section (Task 1;
// checkBackupDirectory enforces the section's own constraints beyond what
// the schema alone expresses).
const SectionName = "backup"

// Settings is the "backup" section (Shared contract Settings row).
type Settings struct {
	KEKEscrowConfirmed bool   `json:"kekEscrowConfirmed"`
	Schedule           string `json:"schedule"`
	RetainCount        int    `json:"retainCount"`
	Directory          string `json:"directory"`
}

// Service streams on-demand backups (createBackup) and runs the scheduled
// backup job (ScheduleArgs/RunScheduled), sharing one settings/status view
// (Status) with GET /backup/status and /readyz's "backup" check.
type Service struct {
	Pool *pgxpool.Pool
	// Settings reads the live "backup" section and persists StatusKey.
	Settings *settings.Store
	// Audit records backup.failed as the system actor (RunScheduled only;
	// createBackup's own backup.created audit is the API handler's job,
	// as the requesting principal). nil in tests that don't exercise it.
	Audit *audit.Auditor
	// Emitter raises backup.completed/backup.failed notification events
	// (RunScheduled only). nil in tests, and in serve.go until Task 14
	// wires notify.Service — a nil Emitter simply emits nothing.
	Emitter *notify.Emitter
	Log     *slog.Logger

	// BaseKey, KEKID, PreviousKEKIDs and AppVersion feed WriteOpts directly
	// (serve.go derives BaseKey once at boot, before clear(root):
	// Deviations R6). BaseKey must be cleared by the caller at process
	// shutdown, not by Service. RootSealed is deliberately not a field
	// here (batch-4 review, Critical): Write now reads the current
	// crypto.root row live, inside its own snapshot transaction, instead
	// of trusting a value the caller captured once and may have gone
	// stale since (a KEK rewrap re-seals the row independently of any
	// backup).
	BaseKey        []byte
	KEKID          string
	PreviousKEKIDs []string
	AppVersion     string

	// Now overrides time.Now (tests only).
	Now func() time.Time
	// StreamFunc overrides Stream's implementation (tests only, same
	// convention as monitor.Service.Dial): nil uses Write against Pool.
	// TestCreateBackupMidStreamErrorAborts sets this to a func that writes
	// a few genuine bytes and then fails, to exercise createBackup's
	// mid-stream abort without corrupting a real database.
	StreamFunc func(ctx context.Context, w io.Writer) (Summary, error)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Stream writes one on-demand backup archive to w (Write, using the
// Service's own configured key material). It does not update Status or
// audit anything itself — createBackup does that once Stream has fully
// returned, and the scheduled job goes through runOnce instead, which also
// handles the file and retention.
func (s *Service) Stream(ctx context.Context, w io.Writer) (Summary, error) {
	if s.StreamFunc != nil {
		return s.StreamFunc(ctx, w)
	}
	return Write(ctx, s.Pool, w, WriteOpts{
		BaseKey:        s.BaseKey,
		KEKID:          s.KEKID,
		PreviousKEKIDs: s.PreviousKEKIDs,
		AppVersion:     s.AppVersion,
	})
}

// EscrowConfirmed reports the live "backup" section's kekEscrowConfirmed
// (createBackup's own 409 gate).
func (s *Service) EscrowConfirmed(ctx context.Context) (bool, error) {
	set, err := s.settings(ctx)
	if err != nil {
		return false, err
	}
	return set.KEKEscrowConfirmed, nil
}

// RecordOnDemandSuccess updates the shared status row after a successful
// createBackup stream: LastSuccessAt/LastSizeBytes move, but LastFile is
// left untouched (Shared contract: "null for an on-demand download", so an
// on-demand backup — never written to disk — must never appear to be one
// of the retained scheduled files).
func (s *Service) RecordOnDemandSuccess(ctx context.Context, sizeBytes int64) error {
	rec, err := s.loadStatus(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	rec.LastSuccessAt = &now
	rec.LastSizeBytes = &sizeBytes
	rec.LastError = ""
	return s.saveStatus(ctx, rec)
}

// settings reads the live "backup" section: its stored value, or the
// section's own default when it was never saved (same convention as
// notify.Current) — never cached, since an operator can flip schedule or
// escrow at any time and the very next request or job run must see it.
func (s *Service) settings(ctx context.Context) (Settings, error) {
	var raw json.RawMessage
	err := s.Settings.Get(ctx, settings.SectionKey(SectionName), &raw)
	if errors.Is(err, settings.ErrNotFound) {
		raw = json.RawMessage(`{"kekEscrowConfirmed":false,"schedule":"off","retainCount":7}`)
	} else if err != nil {
		return Settings{}, err
	}
	var set Settings
	if err := json.Unmarshal(raw, &set); err != nil {
		return Settings{}, err
	}
	return set, nil
}
