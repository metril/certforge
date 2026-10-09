//go:build integration

package deploy

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/targets"
)

type captureInserter struct{ args []DeployArgs }

func (c *captureInserter) InsertTx(_ context.Context, _ pgx.Tx, args river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	c.args = append(c.args, args.(DeployArgs))
	return &rivertype.JobInsertResult{}, nil
}

// A re-enqueue of the same (grant, version) must produce distinct job args
// (river uniqueness would otherwise drop it while a stale job runs), and the
// stale job must not mark the re-armed row deployed.
func TestEnqueueSameVersionTwiceStaleJobIsNoop(t *testing.T) {
	f := newDispatcherFixture(t)
	ins := &captureInserter{}
	f.disp.River = ins
	ctx := context.Background()
	certID := f.cert(t, "seq")
	versionID := f.version(t, certID, "1", false)
	targetID, _ := f.target(t, "seq-target", targets.Server, targets.Never,
		map[string]any{"url": "https://example.test/hook", "token": "tok-seq"})
	grantID := f.grant(t, certID, targetID)

	for i := 0; i < 2; i++ {
		if err := f.disp.enqueueTx(ctx, grantID, &versionID); err != nil {
			t.Fatal(err)
		}
	}
	if len(ins.args) != 2 || ins.args[0] == ins.args[1] {
		t.Fatalf("job args = %+v, want two distinct", ins.args)
	}
	w := &DeployWorker{D: f.disp}
	if err := w.Work(ctx, &river.Job[DeployArgs]{Args: ins.args[0]}); err != nil {
		t.Fatal(err)
	}
	if got := f.status(t, grantID); got != "pending" {
		t.Fatalf("stale job changed status to %q, want pending", got)
	}
	if err := w.Work(ctx, &river.Job[DeployArgs]{Args: ins.args[1]}); err != nil {
		t.Fatal(err)
	}
	if got := f.status(t, grantID); got != "deployed" {
		t.Fatalf("current job status = %q, want deployed", got)
	}
}

// SweepDeployments re-enqueues server grants behind the cert's current
// version, and leaves up-to-date ones alone.
func TestSweepDeploymentsReenqueuesStale(t *testing.T) {
	f := newDispatcherFixture(t)
	ins := &captureInserter{}
	f.disp.River = ins
	ctx := context.Background()
	certID := f.cert(t, "sweep")
	v1 := f.version(t, certID, "1", false)
	targetID, _ := f.target(t, "sweep-target", targets.Server, targets.Never,
		map[string]any{"url": "https://example.test/hook", "token": "tok-sw"})
	grantID := f.grant(t, certID, targetID)
	f.pending(t, grantID, v1)
	if _, err := f.pool.Exec(ctx, `UPDATE certificates SET current_version_id = $1 WHERE id = $2`, v1, certID); err != nil {
		t.Fatal(err)
	}
	if err := f.disp.SweepDeployments(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ins.args) != 0 {
		t.Fatalf("fresh pending row swept: %+v", ins.args)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE server_deployments SET updated_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if err := f.disp.SweepDeployments(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ins.args) != 1 || ins.args[0].GrantID != grantID || ins.args[0].VersionID != v1 {
		t.Fatalf("old pending row: args = %+v", ins.args)
	}
	v2 := f.version(t, certID, "2", false)
	if _, err := f.pool.Exec(ctx, `UPDATE certificates SET current_version_id = $1 WHERE id = $2`, v2, certID); err != nil {
		t.Fatal(err)
	}
	if err := f.disp.SweepDeployments(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ins.args) != 2 || ins.args[1].VersionID != v2 {
		t.Fatalf("lagging row: args = %+v", ins.args)
	}
}
