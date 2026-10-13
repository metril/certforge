//go:build integration

package deploy

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/audit"
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
