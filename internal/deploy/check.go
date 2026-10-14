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
)

// GrantCheckArgs mirrors monitor.CheckArgs (same kind, JSON and uniqueness, so
// a job inserted here is deduplicated against the monitor package's own and
// run by its worker). It is duplicated because monitor imports notify, which
// imports deploy; a test in internal/monitor pins the two together.
type GrantCheckArgs struct {
	MonitorID uuid.UUID `json:"monitor_id"`
}

// Kind implements river.JobArgs.
func (GrantCheckArgs) Kind() string { return "certforge_monitor_check" }

// InsertOpts must equal monitor.CheckArgs.InsertOpts.
func (GrantCheckArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending,
				rivertype.JobStateRunning, rivertype.JobStateRetryable, rivertype.JobStateScheduled},
		},
	}
}

// enqueueGrantCheckTx schedules the grant's verify check, delayed by its
// monitor's post-deploy delay (column default 15s; post actions return before
// services finish reloading, and a too-early mismatch would burn a remediation
// attempt), inside tx. No monitor or a disabled one is a
// no-op. River merges GrantCheckArgs.InsertOpts (unique by args, max attempts)
// with the ScheduledAt passed here, so a check already queued absorbs this one.
func (d *Dispatcher) enqueueGrantCheckTx(ctx context.Context, tx pgx.Tx, grantID uuid.UUID) error {
	m, err := d.Q.WithTx(tx).GetMonitorByGrant(ctx, &grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !m.Enabled {
		return nil
	}
	delay := time.Duration(m.PostDeployDelaySeconds) * time.Second
	_, err = d.River.InsertTx(ctx, tx, GrantCheckArgs{MonitorID: m.ID}, &river.InsertOpts{ScheduledAt: time.Now().Add(delay)})
	return err
}

// EnqueueGrantCheck is enqueueGrantCheckTx in its own transaction.
func (d *Dispatcher) EnqueueGrantCheck(ctx context.Context, grantID uuid.UUID) error {
	if err := pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error { return d.enqueueGrantCheckTx(ctx, tx, grantID) }); err != nil {
		return fmt.Errorf("enqueue grant check: %w", err)
	}
	return nil
}
