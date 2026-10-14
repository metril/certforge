//go:build integration

package deploy

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/metrics"
	"github.com/metril/certforge/internal/targets"
)

type driftFixture struct {
	*dispatcherFixture
	ins     *captureInserter
	grant   uuid.UUID
	version uuid.UUID
	monitor uuid.UUID
}

func newDriftFixture(t *testing.T, autoRemediate bool, status string) *driftFixture {
	t.Helper()
	f := &driftFixture{dispatcherFixture: newDispatcherFixture(t), ins: &captureInserter{}}
	f.disp.River = f.ins
	f.disp.Auditor = audit.New(f.pool, bytes.Repeat([]byte{7}, 32))
	ctx := context.Background()
	certID := f.cert(t, "drift")
	f.version = f.version0(t, certID)
	tgt, _ := f.target(t, "drift-target", targets.Server, targets.Never, map[string]any{"url": "https://example.test/hook", "token": "tok"})
	f.grant = f.dispatcherFixture.grant(t, certID, tgt)
	if _, err := f.pool.Exec(ctx, `UPDATE client_cert_grants SET auto_remediate = $1 WHERE id = $2`, autoRemediate, f.grant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE certificates SET current_version_id = $1 WHERE id = $2`, f.version, certID); err != nil {
		t.Fatal(err)
	}
	f.pending(t, f.grant, f.version)
	if _, err := f.pool.Exec(ctx, `UPDATE server_deployments SET status = $1 WHERE grant_id = $2`, status, f.grant); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `INSERT INTO external_monitors (org_id, name, host, port, grant_id) VALUES ($1, 'm', 'example.test', 443, $2) RETURNING id`,
		f.org, f.grant).Scan(&f.monitor); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *driftFixture) version0(t *testing.T, certID uuid.UUID) uuid.UUID {
	return f.dispatcherFixture.version(t, certID, "1", false)
}

func (f *driftFixture) check(t *testing.T, state, observed string) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	after, err := f.disp.OnCheck(ctx, tx, f.monitor, state, observed, "expected0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if after != nil {
		after()
	}
}

func (f *driftFixture) counts(t *testing.T) (n int32, fp *string) {
	t.Helper()
	if err := f.pool.QueryRow(context.Background(), `SELECT remediations, remediated_fp FROM server_deployments WHERE grant_id = $1`, f.grant).Scan(&n, &fp); err != nil {
		t.Fatal(err)
	}
	return
}

func (f *driftFixture) auditRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'deployment.drift' AND resource_id = $1`, f.grant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDriftMismatchMarksDriftAndAudits(t *testing.T) {
	f := newDriftFixture(t, false, "deployed")
	f.check(t, "mismatch", "observed0123456789")
	if got := f.status(t, f.grant); got != "drift" {
		t.Fatalf("status = %q, want drift", got)
	}
	if f.auditRows(t) != 1 || len(f.ins.args) != 0 {
		t.Fatalf("audit rows = %d, jobs = %d; want 1, 0", f.auditRows(t), len(f.ins.args))
	}
	f.check(t, "mismatch", "observed0123456789") // already drift: no second audit row
	if f.auditRows(t) != 1 {
		t.Fatalf("audit rows = %d after repeat, want 1", f.auditRows(t))
	}
}

func TestDriftAutoRemediateEnqueues(t *testing.T) {
	f := newDriftFixture(t, true, "deployed")
	f.check(t, "mismatch", "fpA")
	if got := f.status(t, f.grant); got != "pending" {
		t.Fatalf("status = %q, want pending", got)
	}
	if n, fp := f.counts(t); n != 1 || fp == nil || *fp != "fpA" || len(f.ins.args) != 1 {
		t.Fatalf("remediations = %d fp = %v jobs = %d; want 1, fpA, 1", n, fp, len(f.ins.args))
	}
}

func TestDriftFlapGuardAndFingerprintReset(t *testing.T) {
	f := newDriftFixture(t, true, "deployed")
	for i := 1; i <= 3; i++ {
		f.check(t, "mismatch", "fpA")
		if n, _ := f.counts(t); n != int32(i) {
			t.Fatalf("cycle %d remediations = %d", i, n)
		}
		// the redeploy completes and the endpoint still serves fpA
		if _, err := f.pool.Exec(context.Background(), `UPDATE server_deployments SET status = 'deployed' WHERE grant_id = $1`, f.grant); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.ins.args) != 3 {
		t.Fatalf("jobs = %d, want 3", len(f.ins.args))
	}
	f.check(t, "mismatch", "fpA")
	if len(f.ins.args) != 3 {
		t.Fatalf("4th cycle enqueued a job")
	}
	if got := f.status(t, f.grant); got != "drift" {
		t.Fatalf("status = %q, want drift", got)
	}
	if got := f.lastError(t, f.grant); got != "auto-remediation did not take effect after 3 attempts" {
		t.Fatalf("last_error = %q", got)
	}
	if f.auditRows(t) != 1 {
		t.Fatalf("audit rows = %d across one episode, want 1", f.auditRows(t))
	}
	f.check(t, "mismatch", "fpB") // a different fingerprint restarts the count
	if n, fp := f.counts(t); n != 1 || *fp != "fpB" || len(f.ins.args) != 4 {
		t.Fatalf("remediations = %d fp = %v jobs = %d; want 1, fpB, 4", n, fp, len(f.ins.args))
	}
	if f.auditRows(t) != 1 { // still the same unrecovered drift: no new audit row
		t.Fatalf("audit rows = %d after a new fingerprint, want 1", f.auditRows(t))
	}
}

func TestDriftAttemptCapFromHook(t *testing.T) {
	f := newDriftFixture(t, true, "deployed")
	f.disp.RemediationAttempts = func(context.Context) int { return 2 }
	for i := 1; i <= 2; i++ {
		f.check(t, "mismatch", "fpA")
		if _, err := f.pool.Exec(context.Background(), `UPDATE server_deployments SET status = 'deployed' WHERE grant_id = $1`, f.grant); err != nil {
			t.Fatal(err)
		}
	}
	f.check(t, "mismatch", "fpA")
	if len(f.ins.args) != 2 {
		t.Fatalf("jobs = %d, want 2", len(f.ins.args))
	}
	if got := f.lastError(t, f.grant); got != "auto-remediation did not take effect after 2 attempts" {
		t.Fatalf("last_error = %q", got)
	}
}

// TestDriftIgnoresStaleVersion: between a renewal committing its new version
// and the deploy landing, the monitor compares the old leaf with the new
// expected fingerprint. That is a pending install, not drift.
func TestDriftIgnoresStaleVersion(t *testing.T) {
	f := newDriftFixture(t, true, "deployed")
	var certID uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `SELECT cert_id FROM client_cert_grants WHERE id = $1`, f.grant).Scan(&certID); err != nil {
		t.Fatal(err)
	}
	v2 := f.dispatcherFixture.version(t, certID, "2", false)
	if _, err := f.pool.Exec(context.Background(), `UPDATE certificates SET current_version_id = $1 WHERE id = $2`, v2, certID); err != nil {
		t.Fatal(err)
	}
	f.check(t, "mismatch", "fpA")
	if got := f.status(t, f.grant); got != "deployed" || len(f.ins.args) != 0 || f.auditRows(t) != 0 {
		t.Fatalf("stale version reacted: status %q jobs %d audit %d", got, len(f.ins.args), f.auditRows(t))
	}
}

func TestDriftOkResetsAndPendingUntouched(t *testing.T) {
	f := newDriftFixture(t, true, "deployed")
	f.check(t, "mismatch", "fpA")
	if _, err := f.pool.Exec(context.Background(), `UPDATE server_deployments SET status = 'drift' WHERE grant_id = $1`, f.grant); err != nil {
		t.Fatal(err)
	}
	f.check(t, "ok", "expected0123456789")
	if n, fp := f.counts(t); f.status(t, f.grant) != "deployed" || n != 0 || fp != nil {
		t.Fatalf("status = %q remediations = %d fp = %v; want deployed, 0, nil", f.status(t, f.grant), n, fp)
	}

	p := newDriftFixture(t, true, "pending")
	p.check(t, "mismatch", "fpA")
	if got := p.status(t, p.grant); got != "pending" || len(p.ins.args) != 0 || p.auditRows(t) != 0 {
		t.Fatalf("pending touched: status %q jobs %d audit %d", got, len(p.ins.args), p.auditRows(t))
	}
}

func TestDeployNudgesGrantMonitor(t *testing.T) {
	f := newDriftFixture(t, false, "pending")
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE external_monitors SET next_check_at = now() + interval '1 hour' WHERE id = $1`, f.monitor); err != nil {
		t.Fatal(err)
	}
	if err := f.disp.Deploy(ctx, f.grant, f.version); err != nil {
		t.Fatal(err)
	}
	var next time.Time
	if err := f.pool.QueryRow(ctx, `SELECT next_check_at FROM external_monitors WHERE id = $1`, f.monitor).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if next.After(time.Now()) {
		t.Fatalf("next_check_at = %v, want <= now", next)
	}
}

// A successful deploy schedules the grant's check after its monitor's delay.
func TestDeploySchedulesCheckAfterDelay(t *testing.T) {
	f := newDriftFixture(t, false, "pending")
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE external_monitors SET post_deploy_delay_seconds = 30 WHERE id = $1`, f.monitor); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	if err := f.disp.Deploy(ctx, f.grant, f.version); err != nil {
		t.Fatal(err)
	}
	if len(f.ins.checks) != 1 || f.ins.checks[0].MonitorID != f.monitor {
		t.Fatalf("checks = %v, want one for %v", f.ins.checks, f.monitor)
	}
	at := f.ins.opts[0].ScheduledAt
	if at.Before(before.Add(30*time.Second)) || at.After(time.Now().Add(31*time.Second)) {
		t.Fatalf("ScheduledAt = %v, want about now+30s", at)
	}
}

func TestDeployDefaultDelayIs15s(t *testing.T) {
	f := newDriftFixture(t, false, "pending")
	before := time.Now()
	if err := f.disp.Deploy(context.Background(), f.grant, f.version); err != nil {
		t.Fatal(err)
	}
	if len(f.ins.opts) != 1 || f.ins.opts[0].ScheduledAt.Before(before.Add(15*time.Second)) || f.ins.opts[0].ScheduledAt.After(time.Now().Add(16*time.Second)) {
		t.Fatalf("opts = %v, want ScheduledAt about now+15s", f.ins.opts)
	}
}

func TestDeployNoCheckWithoutEnabledMonitor(t *testing.T) {
	ctx := context.Background()
	f := newDriftFixture(t, false, "pending")
	if _, err := f.pool.Exec(ctx, `UPDATE external_monitors SET enabled = false WHERE id = $1`, f.monitor); err != nil {
		t.Fatal(err)
	}
	if err := f.disp.Deploy(ctx, f.grant, f.version); err != nil {
		t.Fatal(err)
	}
	if len(f.ins.checks) != 0 {
		t.Fatalf("disabled monitor: checks = %v, want none", f.ins.checks)
	}
	g := newDriftFixture(t, false, "pending")
	if _, err := g.pool.Exec(ctx, `DELETE FROM external_monitors WHERE id = $1`, g.monitor); err != nil {
		t.Fatal(err)
	}
	if err := g.disp.Deploy(ctx, g.grant, g.version); err != nil {
		t.Fatal(err)
	}
	if len(g.ins.checks) != 0 {
		t.Fatalf("no monitor: checks = %v, want none", g.ins.checks)
	}
}

func TestDeployFailedOrStaleSchedulesNoCheck(t *testing.T) {
	ctx := context.Background()
	f := newDriftFixture(t, false, "pending")
	// Stale: deploying a version the row is not pending on is a no-op.
	if err := f.disp.Deploy(ctx, f.grant, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if len(f.ins.checks) != 0 {
		t.Fatalf("stale: checks = %v, want none", f.ins.checks)
	}
	// Failed deploy.
	if _, err := f.pool.Exec(ctx, `UPDATE deploy_targets SET type = 'no-such-type' WHERE id = (SELECT deploy_target_id FROM client_cert_grants WHERE id = $1)`, f.grant); err != nil {
		t.Fatal(err)
	}
	_ = f.disp.Deploy(ctx, f.grant, f.version)
	if len(f.ins.checks) != 0 {
		t.Fatalf("failed: checks = %v, want none", f.ins.checks)
	}
}

func TestEnqueueGrantCheck(t *testing.T) {
	f := newDriftFixture(t, false, "deployed")
	if err := f.disp.EnqueueGrantCheck(context.Background(), f.grant); err != nil {
		t.Fatal(err)
	}
	if len(f.ins.checks) != 1 || f.ins.checks[0].MonitorID != f.monitor {
		t.Fatalf("checks = %v, want one for %v", f.ins.checks, f.monitor)
	}
}

type fakeEvents struct{ drifts []DeployDrift }

func (e *fakeEvents) DeployFailed(context.Context, DeployFailure) error { return nil }
func (e *fakeEvents) DeployDrift(_ context.Context, d DeployDrift) error {
	e.drifts = append(e.drifts, d)
	return nil
}

// TestDriftSendsOneAlertPerEpisode: the first mismatch sends deploy.drift; a
// repeat while drifted sends nothing, and neither does a missing Auditor.
func TestDriftSendsOneAlertPerEpisode(t *testing.T) {
	f := newDriftFixture(t, false, "deployed")
	ev := &fakeEvents{}
	f.disp.Events = ev
	f.disp.Auditor = nil
	driftBefore := testutil.ToFloat64(metrics.DeploymentTransitions.WithLabelValues("server", "drift"))
	okBefore := testutil.ToFloat64(metrics.DeploymentTransitions.WithLabelValues("server", "ok"))
	f.check(t, "mismatch", "observed0123456789")
	if len(ev.drifts) != 1 || ev.drifts[0].GrantID != f.grant || ev.drifts[0].VersionID != f.version ||
		ev.drifts[0].CertName != "drift" || ev.drifts[0].TargetName != "drift-target" {
		t.Fatalf("after first mismatch: %+v", ev.drifts)
	}
	f.check(t, "mismatch", "observed0123456789")
	if len(ev.drifts) != 1 {
		t.Fatalf("a repeated mismatch sent %d alerts, want 1", len(ev.drifts))
	}
	if got := testutil.ToFloat64(metrics.DeploymentTransitions.WithLabelValues("server", "drift")) - driftBefore; got != 1 {
		t.Fatalf("drift transitions = %v, want 1", got)
	}
	f.check(t, "ok", "")
	f.check(t, "ok", "") // already ok: not a transition
	if got := testutil.ToFloat64(metrics.DeploymentTransitions.WithLabelValues("server", "ok")) - okBefore; got != 1 {
		t.Fatalf("ok transitions = %v, want 1", got)
	}
}
