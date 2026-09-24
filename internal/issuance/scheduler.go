package issuance

import (
	"context"
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

// EnqueueDue marks expired certificates, closes stale attempts and enqueues
// due certificates. It returns how many new jobs were inserted (duplicates of
// queued or running jobs are skipped by the unique options).
func EnqueueDue(ctx context.Context, s *Store, ins Inserter, limit int) (int, error) {
	if _, err := s.MarkExpired(ctx); err != nil {
		return 0, err
	}
	if _, err := s.FailStaleAttempts(ctx, 4*time.Hour); err != nil {
		return 0, err
	}
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

// NewRiver builds the river client with the issuance workers and the 5-minute
// periodic scan. The caller starts and stops it.
func NewRiver(pool *pgxpool.Pool, issue *IssueWorker, store *Store, logger *slog.Logger) (*river.Client[pgx.Tx], error) {
	workers := river.NewWorkers()
	river.AddWorker(workers, issue)
	river.AddWorker(workers, &ScheduleWorker{Store: store})
	return river.NewClient(riverpgxv5.New(pool), &river.Config{
		Logger:  logger,
		Queues:  map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 4}},
		Workers: workers,
		// IssueWorker may legitimately run 3h (manual-dns); do not rescue it early.
		RescueStuckJobsAfter: 4 * time.Hour,
		PeriodicJobs: []*river.PeriodicJob{
			river.NewPeriodicJob(river.PeriodicInterval(SchedulePeriod),
				func() (river.JobArgs, *river.InsertOpts) { return ScheduleArgs{}, nil },
				&river.PeriodicJobOpts{RunOnStart: true}),
		},
	})
}
