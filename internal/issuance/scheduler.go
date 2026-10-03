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

// EnqueueDue marks expired certificates, closes stale attempts, prunes old
// rate-ledger rows, issuance attempts and hook runs, and enqueues due
// certificates. The housekeeping
// calls are best-effort: a failure never stops due certificates from being
// enqueued, and is returned (joined) alongside the count once enqueueing is
// done. It returns how many new jobs were inserted (duplicates of queued or
// running jobs are skipped by the unique options).
func EnqueueDue(ctx context.Context, s *Store, ins Inserter, limit int) (int, error) {
	var housekeeping []error
	if _, err := s.MarkExpired(ctx); err != nil {
		housekeeping = append(housekeeping, fmt.Errorf("mark expired: %w", err))
	}
	if _, err := s.FailStaleAttempts(ctx, 4*time.Hour); err != nil {
		housekeeping = append(housekeeping, fmt.Errorf("fail stale attempts: %w", err))
	}
	if _, err := s.PruneLedger(ctx, time.Now().Add(-ledgerRetention)); err != nil {
		housekeeping = append(housekeeping, fmt.Errorf("prune ledger: %w", err))
	}
	if _, err := s.PruneIssuanceAttempts(ctx, time.Now().Add(-attemptRetention), attemptsKeptPerCert); err != nil {
		housekeeping = append(housekeeping, fmt.Errorf("prune issuance attempts: %w", err))
	}
	if _, err := s.PruneHookRuns(ctx, time.Now().Add(-hookRunRetention)); err != nil {
		housekeeping = append(housekeeping, fmt.Errorf("prune hook runs: %w", err))
	}
	if _, err := s.PruneExpiredManualPending(ctx); err != nil {
		housekeeping = append(housekeeping, fmt.Errorf("prune expired manual dns: %w", err))
	}
	ids, err := s.DueCertificateIDs(ctx, limit)
	if err != nil {
		return 0, errors.Join(append(housekeeping, err)...)
	}
	n := 0
	for _, id := range ids {
		res, err := ins.Insert(ctx, IssueArgs{CertID: id}, nil)
		if err != nil {
			return n, errors.Join(append(housekeeping, err)...)
		}
		if !res.UniqueSkippedAsDuplicate {
			n++
		}
	}
	return n, errors.Join(housekeeping...)
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
