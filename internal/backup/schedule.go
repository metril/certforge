package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/riverqueue/river"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/notify"
)

// scheduleFailureBackoff bounds how soon a scheduled backup retries after
// a failure (task-12 brief: "does nothing ... within 1 h after a
// failure"), so a persistently failing backup (a full disk, a revoked
// directory) does not retry every hour and spam backup.failed events —
// the next hourly ScheduleArgs run simply no-ops until the hour is up.
const scheduleFailureBackoff = time.Hour

// maxLastError bounds Status.LastError/statusRecord.LastError (schema:
// BackupStatus.lastError, <= 1000).
const maxLastError = 1000

// ScheduleArgs is the hourly scheduled-backup job (Shared contract:
// certforge_backup, hourly, RunOnStart).
type ScheduleArgs struct{}

// Kind implements river.JobArgs.
func (ScheduleArgs) Kind() string { return "certforge_backup" }

// ScheduleWorker runs ScheduleArgs.
type ScheduleWorker struct {
	river.WorkerDefaults[ScheduleArgs]
	S *Service
}

// Work implements river.Worker. RunScheduled never itself returns an error
// for an ordinary backup failure (recorded via Status/audit/notify
// instead), so this job is never retried by river on top of the job's own
// due/backoff logic; only a settings-read failure (a database problem)
// propagates, letting river's own retry apply.
func (w *ScheduleWorker) Work(ctx context.Context, _ *river.Job[ScheduleArgs]) error {
	return w.S.RunScheduled(ctx)
}

// RegisterRiver is an issuance.RiverExtra: ScheduleWorker plus the hourly
// job, RunOnStart so a freshly started server that missed its window while
// down catches up immediately rather than waiting up to an hour.
func (s *Service) RegisterRiver(workers *river.Workers) []*river.PeriodicJob {
	river.AddWorker(workers, &ScheduleWorker{S: s})
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(time.Hour),
		func() (river.JobArgs, *river.InsertOpts) { return ScheduleArgs{}, nil },
		&river.PeriodicJobOpts{RunOnStart: true})}
}

// due reports whether a scheduled backup should run now (task-12 brief):
// never when schedule is off, not within scheduleFailureBackoff of the
// last failure, and otherwise only once the schedule's own cadence has
// elapsed since the last scheduled success (immediately, if there has
// never been one). lastScheduled is statusRecord.LastScheduledAt (final
// review fix wave, finding 2) — never LastSuccessAt, which an on-demand
// download also moves and must not be able to postpone this.
func due(schedule string, lastScheduled, lastFailure *time.Time, now time.Time) bool {
	if schedule != "daily" && schedule != "weekly" {
		return false
	}
	if lastFailure != nil && now.Sub(*lastFailure) < scheduleFailureBackoff {
		return false
	}
	if lastScheduled == nil {
		return true
	}
	return !now.Before(nextRunAt(schedule, lastScheduled, now))
}

// RunScheduled runs the scheduled-backup job once: a no-op when the
// schedule isn't due (due), otherwise a full attempt (runOnce), whose own
// success or failure is recorded on Status and, on failure, audited and
// logged — never returned as this job's own error (see Work's doc
// comment).
func (s *Service) RunScheduled(ctx context.Context) error {
	set, err := s.settings(ctx)
	if err != nil {
		return fmt.Errorf("backup: scheduled backup: read settings: %w", err)
	}
	rec, err := s.loadStatus(ctx)
	if err != nil {
		return fmt.Errorf("backup: scheduled backup: read status: %w", err)
	}
	now := s.now()
	if !due(set.Schedule, rec.LastScheduledAt, rec.LastFailureAt, now) {
		return nil
	}
	if err := s.runOnce(ctx, set, now); err != nil {
		s.log().Error("backup: scheduled backup failed", "err", err)
	}
	return nil
}

// runOnce performs one scheduled backup attempt: writes a fresh archive to
// a temp file in set.Directory and renames it into place (0600, tmp plus
// rename — a reader never sees a partial file at the final name), prunes
// beyond set.RetainCount, and records the outcome. It returns the failure
// cause (already recorded), never a "please retry me" signal.
//
// Its own status write is an atomic merge (mergeStatus), never a
// Get-then-Set of a snapshot loaded before the (possibly slow) Stream call
// above (final review fix wave, finding 2): a concurrent write to a field
// this run doesn't itself set (for instance an on-demand download's own
// LastSuccessAt/LastSizeBytes, or a failure recorded by some other path)
// would otherwise be blindly reverted to whatever this run's own stale
// pre-Stream snapshot held for it.
func (s *Service) runOnce(ctx context.Context, set Settings, now time.Time) error {
	name := fmt.Sprintf("certforge-%s.cfbak", now.UTC().Format("20060102T150405Z"))
	dest := filepath.Join(set.Directory, name)
	tmp := dest + ".tmp"

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return s.recordFailure(ctx, now, fmt.Errorf("open temp file: %w", err))
	}
	summary, werr := s.Stream(ctx, f)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return s.recordFailure(ctx, now, fmt.Errorf("write archive: %w", werr))
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return s.recordFailure(ctx, now, fmt.Errorf("rename archive: %w", err))
	}

	if err := prune(set.Directory, set.RetainCount); err != nil {
		s.log().Error("backup: prune failed", "dir", set.Directory, "err", err)
	}

	success := now
	sz := summary.SizeBytes
	empty := ""
	if err := s.mergeStatus(ctx, statusPatch{
		LastSuccessAt:   &success,
		LastScheduledAt: &success,
		LastFile:        &name,
		LastSizeBytes:   &sz,
		LastError:       &empty,
	}); err != nil {
		return fmt.Errorf("backup: save status: %w", err)
	}
	s.emitCompleted(ctx, name, summary.SizeBytes)
	return nil
}

// recordFailure merges the failure into the shared status row, emits
// backup.failed and audits it (system actor), then returns cause unchanged
// so runOnce's caller can log it. Best-effort: a mergeStatus/emit/audit
// error here is logged, never compounding the original failure.
func (s *Service) recordFailure(ctx context.Context, now time.Time, cause error) error {
	failure := now
	errMsg := clip(cause.Error(), maxLastError)
	if err := s.mergeStatus(ctx, statusPatch{LastFailureAt: &failure, LastError: &errMsg}); err != nil {
		s.log().Error("backup: save failure status", "err", err)
	}
	s.emitFailed(ctx, now, errMsg)
	return cause
}

// prune deletes the oldest certforge-*.cfbak files in dir beyond retain,
// keeping the most recent retain files. File names sort lexically in
// chronological order (certforge-<yyyymmddThhmmssZ>.cfbak), so no parsing
// is needed.
func prune(dir string, retain int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("backup: list %s: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "certforge-") && strings.HasSuffix(name, ".cfbak") {
			files = append(files, name)
		}
	}
	if retain < 0 {
		retain = 0
	}
	if len(files) <= retain {
		return nil
	}
	sort.Strings(files)
	var firstErr error
	for _, f := range files[:len(files)-retain] {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("backup: remove %s: %w", f, err)
		}
	}
	return firstErr
}

// emitCompleted raises backup.completed (Shared contract: details {file,
// sizeBytes}, dedupe key "backup.completed:<file>"). s.Emitter is nil in
// tests and until Task 14 wires notify.Service into serve.go.
func (s *Service) emitCompleted(ctx context.Context, file string, sizeBytes int64) {
	if s.Emitter == nil {
		return
	}
	ev := notify.Event{
		Kind:      "backup.completed",
		Resource:  notify.Resource{ID: file, Name: file},
		Summary:   fmt.Sprintf("Backup %s completed (%d bytes)", file, sizeBytes),
		Details:   map[string]any{"file": file, "sizeBytes": sizeBytes},
		DedupeKey: "backup.completed:" + file,
	}
	if _, err := s.Emitter.Emit(ctx, nil, ev); err != nil {
		s.log().Error("backup: emit backup.completed failed", "err", err)
	}
}

// emitFailed raises backup.failed (Shared contract: dedupe key
// "backup.failed:<UTC hour>", so repeated failures within the same hour
// collapse into one event) and audits backup.failed as the system actor
// (Shared contract's Audit row).
func (s *Service) emitFailed(ctx context.Context, now time.Time, lastError string) {
	if s.Emitter != nil {
		ev := notify.Event{
			Kind:      "backup.failed",
			Resource:  notify.Resource{ID: "backup", Name: "backup"},
			Summary:   "Scheduled backup failed",
			Details:   map[string]any{"error": lastError},
			DedupeKey: "backup.failed:" + now.UTC().Format("2006010215"),
		}
		if _, err := s.Emitter.Emit(ctx, nil, ev); err != nil {
			s.log().Error("backup: emit backup.failed failed", "err", err)
		}
	}
	if s.Audit != nil {
		if err := s.Audit.Record(ctx, audit.Event{
			Action: "backup.failed", ResourceType: "backup", ActorType: "system",
			Details: map[string]any{"error": lastError},
		}); err != nil {
			s.log().Error("backup: audit backup.failed failed", "err", err)
		}
	}
}

// clip truncates s to at most maxBytes bytes on a valid UTF-8 boundary
// (same trick as notify's own truncateUTF8: an incomplete trailing
// sequence would make Postgres reject the string outright).
func clip(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size != 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}
