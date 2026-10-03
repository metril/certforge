package issuance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"
)

// Inserter enqueues jobs; *river.Client[pgx.Tx] implements it.
type Inserter interface {
	Insert(ctx context.Context, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error)
}

// ScheduleArgs is the periodic scan job.
type ScheduleArgs struct{}

// Kind implements river.JobArgs.
func (ScheduleArgs) Kind() string { return "certforge_schedule" }

// ScheduleWorker enqueues an IssueArgs job for every due certificate.
type ScheduleWorker struct {
	river.WorkerDefaults[ScheduleArgs]
	Store    *Store
	Inserter Inserter // nil = the river client running this job
}

// Timeout bounds one scan: the housekeeping steps each have their own
// housekeepingStepTimeout, and enqueueing must always get to run.
func (w *ScheduleWorker) Timeout(*river.Job[ScheduleArgs]) time.Duration { return scheduleTimeout }

// Work implements river.Worker.
func (w *ScheduleWorker) Work(ctx context.Context, _ *river.Job[ScheduleArgs]) error {
	ins := w.Inserter
	if ins == nil {
		ins = river.ClientFromContext[pgx.Tx](ctx)
	}
	_, err := EnqueueDue(ctx, w.Store, ins, 500)
	return err
}

// ledgerRetention is how long a rate_ledger row is kept before EnqueueDue
// prunes it (Deviations R7): longer than every CheckLedger window (the
// widest is 7 days) so a still-relevant row is never pruned mid-window.
const ledgerRetention = 30 * 24 * time.Hour

// attemptRetention is how long a finished issuance attempt is kept before
// EnqueueDue prunes it, except that each certificate's newest
// attemptsKeptPerCert attempts are always kept however old, so a
// long-stable certificate still shows its last issuance history.
const (
	attemptRetention    = 90 * 24 * time.Hour
	attemptsKeptPerCert = 20
)

// hookRunRetention is how long an agent hook run (with its captured
// output) is kept before EnqueueDue prunes it.
const hookRunRetention = 90 * 24 * time.Hour

// scheduleTimeout is the ScheduleWorker's job timeout (river's default is
// one minute): comfortably above the sum of the steps run in EnqueueDue.
const scheduleTimeout = 5 * time.Minute

// housekeepingStepTimeout bounds each housekeeping step of EnqueueDue, so a
// slow one cannot consume the job's budget. A variable only so tests can
// shorten it.
var housekeepingStepTimeout = 20 * time.Second

// pruneBatchLimit caps the rows one prune deletes per run; a large backlog
// drains over successive runs instead of one long statement.
const pruneBatchLimit = 5000

// EnqueueDue marks expired certificates, closes stale attempts, enqueues due
// certificates, and then prunes old rate-ledger rows, issuance attempts,
// hook runs and expired manual-dns records. Every housekeeping call runs
// under its own timeout and is best-effort: a failure never stops due
// certificates from being enqueued (the prunes run after enqueueing), and
// is returned (joined) alongside the count. It returns how many new jobs
// were inserted (duplicates of queued or running jobs are skipped by the
// unique options).
func EnqueueDue(ctx context.Context, s *Store, ins Inserter, limit int) (int, error) {
	var housekeeping []error
	step := func(name string, fn func(context.Context) error) {
		sctx, cancel := context.WithTimeout(ctx, housekeepingStepTimeout)
		defer cancel()
		if err := fn(sctx); err != nil {
			housekeeping = append(housekeeping, fmt.Errorf("%s: %w", name, err))
		}
	}
	step("mark expired", func(c context.Context) error { _, err := s.MarkExpired(c); return err })
	step("fail stale attempts", func(c context.Context) error { _, err := s.FailStaleAttempts(c, 4*time.Hour); return err })
	n, err := enqueueDue(ctx, s, ins, limit)
	if err != nil {
		housekeeping = append(housekeeping, err)
	}
	step("prune ledger", func(c context.Context) error {
		_, err := s.PruneLedger(c, time.Now().Add(-ledgerRetention))
		return err
	})
	step("prune issuance attempts", func(c context.Context) error {
		_, err := s.PruneIssuanceAttempts(c, time.Now().Add(-attemptRetention), attemptsKeptPerCert, pruneBatchLimit)
		return err
	})
	step("prune hook runs", func(c context.Context) error {
		_, err := s.PruneHookRuns(c, time.Now().Add(-hookRunRetention), pruneBatchLimit)
		return err
	})
	step("prune expired manual dns", func(c context.Context) error { _, err := s.PruneExpiredManualPending(c); return err })
	return n, errors.Join(housekeeping...)
}

func enqueueDue(ctx context.Context, s *Store, ins Inserter, limit int) (int, error) {
	ids, err := s.DueCertificateIDs(ctx, limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		res, err := ins.Insert(ctx, IssueArgs{CertID: id}, nil)
		if err != nil {
			return n, err
		}
		if !res.UniqueSkippedAsDuplicate {
			n++
		}
	}
	return n, nil
}

// SchedulePeriod is how often due certificates are scanned.
const SchedulePeriod = 5 * time.Minute

// ARIPollPeriod is how often the ACME Renewal Information poll runs.
const ARIPollPeriod = 6 * time.Hour

// RiverExtra registers another package's workers and returns its periodic
// jobs (for example the agent listener certificate renewal).
type RiverExtra func(workers *river.Workers) []*river.PeriodicJob

// NewRiver builds the river client with the issuance workers (issue, the
// 5-minute periodic scan, and the 6-hourly ARI poll), and any extras. Every
// field ari needs (Store, Certs, NewSigner, Now, Rand, Log) must already be
// set, same as issue's own fields (cmd/certforge/serve.go, before
// riverClient.Start). The caller starts and stops the returned client.
func NewRiver(pool *pgxpool.Pool, issue *IssueWorker, ari *ARIPollWorker, store *Store, logger *slog.Logger, extras ...RiverExtra) (*river.Client[pgx.Tx], error) {
	workers := river.NewWorkers()
	river.AddWorker(workers, issue)
	river.AddWorker(workers, &ScheduleWorker{Store: store})
	river.AddWorker(workers, ari)
	periodic := []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SchedulePeriod),
			func() (river.JobArgs, *river.InsertOpts) { return ScheduleArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
		river.NewPeriodicJob(river.PeriodicInterval(ARIPollPeriod),
			func() (river.JobArgs, *river.InsertOpts) { return ARIPollArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: false}),
	}
	for _, x := range extras {
		periodic = append(periodic, x(workers)...)
	}
	return river.NewClient(riverpgxv5.New(pool), &river.Config{
		Logger:  logger,
		Queues:  map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 4}},
		Workers: workers,
		// IssueWorker may legitimately run 3h (manual-dns); do not rescue it early.
		RescueStuckJobsAfter: 4 * time.Hour,
		PeriodicJobs:         periodic,
	})
}
