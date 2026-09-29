package monitor

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// scanLimit bounds each minute's scan (Task 9 brief: "the scan runs every
// minute enqueuing due enabled monitors", mirroring notify's own
// scanLimit-per-run convention).
const scanLimit = 500

// scanPeriod is how often ScanArgs runs (Task 9 brief: "the scan runs
// every minute").
const scanPeriod = time.Minute

// Inserter enqueues a job outside any transaction (EnqueueDueChecks runs no
// write of its own to share one with); *river.Client[pgx.Tx] implements it,
// the same shape issuance.Inserter/Inserter uses for its own periodic scan.
type Inserter interface {
	Insert(ctx context.Context, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error)
}

// EnqueueDueChecks enqueues a certforge_monitor_check for every monitor
// DueIDs reports, deduplicated by CheckArgs' own UniqueOpts (a monitor
// already queued, running or scheduled for retry is skipped, not
// double-queued). It returns how many new jobs were actually inserted.
func EnqueueDueChecks(ctx context.Context, store *Store, ins Inserter, limit int) (int, error) {
	ids, err := store.DueIDs(ctx, limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		res, err := ins.Insert(ctx, CheckArgs{MonitorID: id}, nil)
		if err != nil {
			return n, err
		}
		if !res.UniqueSkippedAsDuplicate {
			n++
		}
	}
	return n, nil
}

// ScanArgs is the periodic job that enqueues a certforge_monitor_check for
// every enabled monitor whose next check is due (Shared contract:
// internal/monitor's ScanArgs, kind certforge_monitor_scan, every minute).
type ScanArgs struct{}

// Kind implements river.JobArgs.
func (ScanArgs) Kind() string { return "certforge_monitor_scan" }

// ScanWorker runs ScanArgs. Inserter is nil in production (the river client
// running the job, via river.ClientFromContext) and a fake in tests, the
// same convention issuance.ScheduleWorker uses.
type ScanWorker struct {
	river.WorkerDefaults[ScanArgs]
	Store    *Store
	Inserter Inserter
}

// Work implements river.Worker.
func (w *ScanWorker) Work(ctx context.Context, _ *river.Job[ScanArgs]) error {
	ins := w.Inserter
	if ins == nil {
		ins = river.ClientFromContext[pgx.Tx](ctx)
	}
	_, err := EnqueueDueChecks(ctx, w.Store, ins, scanLimit)
	return err
}

// CheckArgs is one monitor's own check job (Shared contract:
// CheckArgs{MonitorID}, kind certforge_monitor_check).
type CheckArgs struct {
	MonitorID uuid.UUID `json:"monitor_id"`
}

// Kind implements river.JobArgs.
func (CheckArgs) Kind() string { return "certforge_monitor_check" }

// InsertOpts makes a monitor's check job unique per monitor while queued,
// running or scheduled for retry (Task 9 brief: "unique by args"; same
// pattern as deploy.DeployArgs) — the every-minute scan re-running before a
// slow check finishes must not queue a second one behind it.
func (CheckArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending,
				rivertype.JobStateRunning, rivertype.JobStateRetryable, rivertype.JobStateScheduled},
		},
	}
}

// CheckWorker runs CheckArgs.
type CheckWorker struct {
	river.WorkerDefaults[CheckArgs]
	S *Service
}

// Work implements river.Worker.
func (w *CheckWorker) Work(ctx context.Context, job *river.Job[CheckArgs]) error {
	_, err := w.S.Check(ctx, job.Args.MonitorID)
	return err
}

// RegisterRiver is an issuance.RiverExtra: ScanWorker/CheckWorker plus the
// every-minute scan job, RunOnStart so a freshly started server catches up
// on due monitors immediately instead of waiting up to a minute.
func (s *Service) RegisterRiver(workers *river.Workers) []*river.PeriodicJob {
	river.AddWorker(workers, &ScanWorker{Store: s.Store})
	river.AddWorker(workers, &CheckWorker{S: s})
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(scanPeriod),
		func() (river.JobArgs, *river.InsertOpts) { return ScanArgs{}, nil },
		&river.PeriodicJobOpts{RunOnStart: true})}
}
