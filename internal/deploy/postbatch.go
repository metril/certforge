package deploy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/actions"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// postBatchDelay is how long the first parked tail waits for other grants on
// the same target to join its batch. Later grants do not extend the window.
const postBatchDelay = 15 * time.Second

// PostBatchArgs is the river job that runs the parked post-deploy tails of
// every server grant on one deploy target, each identical batchable step once.
type PostBatchArgs struct {
	TargetID uuid.UUID `json:"target_id"`
}

// Kind implements river.JobArgs.
func (PostBatchArgs) Kind() string { return "certforge_server_post_batch" }

// InsertOpts makes the job unique per target while it waits; a running job
// does not block the next one, which picks up tails parked after it started.
func (PostBatchArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 5,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStateScheduled,
				rivertype.JobStatePending},
		},
	}
}

// PostBatchWorker runs PostBatchArgs.
type PostBatchWorker struct {
	river.WorkerDefaults[PostBatchArgs]
	D *Dispatcher
}

// Timeout implements river.Worker.
func (w *PostBatchWorker) Timeout(*river.Job[PostBatchArgs]) time.Duration { return deployTimeout }

// Work implements river.Worker.
func (w *PostBatchWorker) Work(ctx context.Context, job *river.Job[PostBatchArgs]) error {
	return w.D.PostBatch(ctx, job.Args.TargetID)
}

// parkTail records that grantID deployed and only its batchable tail is left,
// and schedules the target's post-batch job, in one transaction.
func (d *Dispatcher) parkTail(ctx context.Context, grantID, targetID, versionID uuid.UUID, seq int64) error {
	return pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		if err := d.Q.WithTx(tx).UpsertPostTail(ctx, sqlcgen.UpsertPostTailParams{GrantID: grantID, DeployTargetID: targetID, VersionID: versionID, DeploySeq: seq}); err != nil {
			return err
		}
		_, err := d.River.InsertTx(ctx, tx, PostBatchArgs{TargetID: targetID}, &river.InsertOpts{ScheduledAt: time.Now().Add(postBatchDelay)})
		return err
	})
}

type batchMember struct {
	plan   *deployPlan
	byID   map[uuid.UUID]stepAction
	failed bool
}

// PostBatch runs the parked tails of the grants on targetID. Tails another
// batch job holds are skipped. Steps are merged (see actions.MergeTails) and
// each runs once, recorded for every grant it ran for. A grant whose tail
// finishes is marked deployed; one that fails keeps its row, and the error
// returned makes river retry the job.
func (d *Dispatcher) PostBatch(ctx context.Context, targetID uuid.UUID) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := d.Q.WithTx(tx)
	rows, err := q.PostTailsForTarget(ctx, targetID)
	if err != nil {
		return err
	}
	members := map[uuid.UUID]*batchMember{}
	tails := map[uuid.UUID][]actions.ActionRef{}
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, r := range rows {
		seq := r.DeploySeq
		p, err := d.prepare(ctx, r.GrantID, r.VersionID, &seq)
		if err != nil {
			note(err)
			continue
		}
		if p == nil { // grant gone or re-armed since the tail was parked
			if err := q.DeletePostTail(ctx, r.GrantID); err != nil {
				return err
			}
			continue
		}
		_, tail := p.postSteps()
		m := &batchMember{plan: p, byID: map[uuid.UUID]stepAction{}}
		refs := make([]actions.ActionRef, len(tail))
		for i, a := range tail {
			m.byID[a.ID] = a
			refs[i] = a.ActionRef
		}
		members[r.GrantID] = m
		tails[r.GrantID] = refs
	}
	for _, ms := range actions.MergeTails(tails, actions.IsBatch) {
		var live []uuid.UUID
		for _, g := range ms.Grants {
			if !members[g].failed {
				live = append(live, g)
			}
		}
		if len(live) == 0 {
			continue
		}
		first := members[live[0]]
		step := first.byID[ms.Ref.ID]
		runErr := d.runActionFor(ctx, first.plan.row, step, first.plan.req, live)
		if runErr == nil {
			continue
		}
		for _, g := range live {
			m := members[g]
			if step.Optional {
				d.log().Warn("deploy: optional post action failed", "grant", g, "action", step.Name, "err", runErr)
				continue
			}
			m.failed = true
			note(d.fail(ctx, m.plan.row, m.plan.versionID, m.plan.seq, m.plan.redact,
				fmt.Errorf("deployed, but post action %s failed: %w", step.Name, runErr)))
		}
	}
	var done []uuid.UUID
	for g, m := range members {
		if m.failed {
			continue
		}
		if err := d.completeTx(ctx, tx, g, m.plan.versionID, m.plan.seq); err != nil {
			return err
		}
		if err := q.DeletePostTail(ctx, g); err != nil {
			return err
		}
		done = append(done, g)
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(firstErr, err)
	}
	for _, g := range done {
		d.nudge(ctx, g)
	}
	return firstErr
}
