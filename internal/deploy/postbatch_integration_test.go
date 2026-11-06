//go:build integration

package deploy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// batchPair is two grants of different certificates on the same ssh target.
type batchPair struct {
	*stepSetup
	g2, ver2 uuid.UUID
}

func newBatchPair(t *testing.T) *batchPair {
	t.Helper()
	u := newStepSetup(t)
	u.useSSHTarget(t, "ssh")
	cert := u.f.cert(t, "web2")
	ver := u.f.version(t, cert, "2", false)
	g := u.f.grant(t, cert, u.ssh)
	u.f.pending(t, g, ver)
	return &batchPair{stepSetup: u, g2: g, ver2: ver}
}

func (p *batchPair) deployBoth(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := p.f.disp.Deploy(ctx, p.g, p.ver); err != nil {
		t.Fatal(err)
	}
	if err := p.f.disp.Deploy(ctx, p.g2, p.ver2); err != nil {
		t.Fatal(err)
	}
}

func (p *batchPair) tails(t *testing.T) int {
	t.Helper()
	var n int
	if err := p.f.pool.QueryRow(context.Background(), `SELECT count(*) FROM server_post_tails`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (p *batchPair) cmds() int {
	p.srv.Mu.Lock()
	defer p.srv.Mu.Unlock()
	return len(p.srv.Cmds)
}

func TestPostBatchSharedStepRunsOnce(t *testing.T) {
	p := newBatchPair(t)
	a := p.sshAction(t, "reload", "post_deploy", "systemctl reload nginx")
	p.f.setSteps(t, p.g, step(a))
	p.f.setSteps(t, p.g2, step(a))
	p.deployBoth(t)
	if st := p.f.status(t, p.g); st != "pending" || p.cmds() != 0 || p.tails(t) != 2 {
		t.Fatalf("before batch: status %s cmds %d tails %d", st, p.cmds(), p.tails(t))
	}
	ins := p.f.disp.River.(*captureInserter)
	if len(ins.post) != 2 || ins.post[0].TargetID != p.ssh {
		t.Fatalf("post jobs = %+v", ins.post)
	}
	if at := ins.postAt[0].ScheduledAt; time.Until(at) < 10*time.Second || time.Until(at) > 20*time.Second {
		t.Fatalf("scheduled at %v", at)
	}
	if err := p.f.disp.PostBatch(context.Background(), p.ssh); err != nil {
		t.Fatal(err)
	}
	if p.cmds() != 1 {
		t.Fatalf("cmds = %d, want 1", p.cmds())
	}
	for _, g := range []uuid.UUID{p.g, p.g2} {
		if st := p.f.status(t, g); st != "deployed" {
			t.Fatalf("status = %s", st)
		}
		if runs := p.f.runs(t, g); len(runs) != 1 || runs[0].action == nil || *runs[0].action != a {
			t.Fatalf("runs = %+v", runs)
		}
	}
	if p.tails(t) != 0 {
		t.Fatal("tails left")
	}
	// A second run finds nothing to do.
	if err := p.f.disp.PostBatch(context.Background(), p.ssh); err != nil || p.cmds() != 1 {
		t.Fatal(err, p.cmds())
	}
}

func TestPostBatchFailureFailsBothThenRetrySucceeds(t *testing.T) {
	p := newBatchPair(t)
	a := p.sshAction(t, "reload", "post_deploy", "reload-it")
	p.f.setSteps(t, p.g, step(a))
	p.f.setSteps(t, p.g2, step(a))
	p.deployBoth(t)
	p.srv.Exit = 3
	if err := p.f.disp.PostBatch(context.Background(), p.ssh); err == nil {
		t.Fatal("expected error")
	}
	for _, g := range []uuid.UUID{p.g, p.g2} {
		if st := p.f.status(t, g); st != "failed" {
			t.Fatalf("status = %s", st)
		}
	}
	if p.tails(t) != 2 || p.cmds() != 1 {
		t.Fatalf("tails %d cmds %d", p.tails(t), p.cmds())
	}
	p.srv.Exit = 0
	if err := p.f.disp.PostBatch(context.Background(), p.ssh); err != nil {
		t.Fatal(err)
	}
	for _, g := range []uuid.UUID{p.g, p.g2} {
		if st := p.f.status(t, g); st != "deployed" {
			t.Fatalf("status = %s", st)
		}
	}
	if p.tails(t) != 0 || p.cmds() != 2 {
		t.Fatalf("tails %d cmds %d", p.tails(t), p.cmds())
	}
}

func TestPostBatchOptionalFailureStillDeploys(t *testing.T) {
	p := newBatchPair(t)
	a := p.sshAction(t, "reload", "post_deploy", "reload-it", actionOpts{optional: true})
	p.f.setSteps(t, p.g, step(a))
	p.f.setSteps(t, p.g2, step(a))
	p.deployBoth(t)
	p.srv.Exit = 3
	if err := p.f.disp.PostBatch(context.Background(), p.ssh); err != nil {
		t.Fatal(err)
	}
	for _, g := range []uuid.UUID{p.g, p.g2} {
		if st := p.f.status(t, g); st != "deployed" {
			t.Fatalf("status = %s", st)
		}
	}
}

// A step that expands the certificate runs per grant, after the shared one.
func TestPostBatchPerGrantStepRunsForEach(t *testing.T) {
	p := newBatchPair(t)
	var hits atomic.Int32
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer hs.Close()
	a := p.sshAction(t, "reload", "post_deploy", "reload-it")
	h := p.f.action(t, "ping", "http", "post_deploy", map[string]any{"method": "POST", "url": hs.URL, "body": "{{cert.name}}"})
	p.f.setSteps(t, p.g, step(a), step(h))
	p.f.setSteps(t, p.g2, step(a), step(h))
	p.deployBoth(t)
	if err := p.f.disp.PostBatch(context.Background(), p.ssh); err != nil {
		t.Fatal(err)
	}
	if p.cmds() != 1 || hits.Load() != 2 {
		t.Fatalf("cmds %d hits %d", p.cmds(), hits.Load())
	}
	for _, g := range []uuid.UUID{p.g, p.g2} {
		if runs := p.f.runs(t, g); len(runs) != 2 {
			t.Fatalf("runs = %+v", runs)
		}
	}
}

// A grant failing its own per-grant step does not fail the other.
func TestPostBatchPerGrantFailureIsolated(t *testing.T) {
	p := newBatchPair(t)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if string(b) == "web" {
			w.WriteHeader(500)
		}
	}))
	defer hs.Close()
	a := p.sshAction(t, "reload", "post_deploy", "reload-it")
	h := p.f.action(t, "ping", "http", "post_deploy", map[string]any{"method": "POST", "url": hs.URL, "body": "{{cert.name}}"})
	p.f.setSteps(t, p.g, step(a), step(h))
	p.f.setSteps(t, p.g2, step(a), step(h))
	p.deployBoth(t)
	if err := p.f.disp.PostBatch(context.Background(), p.ssh); err == nil {
		t.Fatal("expected error")
	}
	if st := p.f.status(t, p.g); st != "failed" {
		t.Fatalf("g status = %s", st)
	}
	if st := p.f.status(t, p.g2); st != "deployed" {
		t.Fatalf("g2 status = %s", st)
	}
	if p.tails(t) != 1 {
		t.Fatalf("tails = %d", p.tails(t))
	}
}

func TestPostBatchStaleSeqSkipped(t *testing.T) {
	p := newBatchPair(t)
	a := p.sshAction(t, "reload", "post_deploy", "reload-it")
	p.f.setSteps(t, p.g, step(a))
	p.f.setSteps(t, p.g2, step(a))
	p.deployBoth(t)
	if _, err := p.f.pool.Exec(context.Background(), `UPDATE server_deployments SET deploy_seq = deploy_seq + 1 WHERE grant_id = $1`, p.g); err != nil {
		t.Fatal(err)
	}
	if err := p.f.disp.PostBatch(context.Background(), p.ssh); err != nil {
		t.Fatal(err)
	}
	if st := p.f.status(t, p.g); st != "pending" {
		t.Fatalf("stale grant status = %s", st)
	}
	if st := p.f.status(t, p.g2); st != "deployed" {
		t.Fatalf("g2 status = %s", st)
	}
	if p.cmds() != 1 || p.tails(t) != 0 {
		t.Fatalf("cmds %d tails %d", p.cmds(), p.tails(t))
	}
}

// Re-arming a grant (the deploy_seq bump) clears its parked tail.
func TestEnqueueClearsParkedTail(t *testing.T) {
	p := newBatchPair(t)
	a := p.sshAction(t, "reload", "post_deploy", "reload-it")
	p.f.setSteps(t, p.g, step(a))
	p.deployBoth(t)
	ctx := context.Background()
	v := p.ver
	if err := p.f.disp.enqueueTx(ctx, p.g, &v); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := p.f.pool.QueryRow(ctx, `SELECT count(*) FROM server_post_tails WHERE grant_id = $1`, p.g).Scan(&n); err != nil || n != 0 {
		t.Fatal(err, n)
	}
}

func TestPostBatchOtherTargetNotMerged(t *testing.T) {
	p := newBatchPair(t)
	a := p.sshAction(t, "reload", "post_deploy", "reload-it")
	p.f.setSteps(t, p.g, step(a))
	p.f.setSteps(t, p.g2, step(a))
	// g2 moves to a second ssh target.
	ssh2 := p.f.sshTarget(t, p.srv, p.srv.Port(t))
	if _, err := p.f.pool.Exec(context.Background(), `UPDATE deploy_targets SET type = 'ssh' WHERE id = $1`, ssh2); err != nil {
		t.Fatal(err)
	}
	if _, err := p.f.pool.Exec(context.Background(), `UPDATE client_cert_grants SET deploy_target_id = $2 WHERE id = $1`, p.g2, ssh2); err != nil {
		t.Fatal(err)
	}
	p.deployBoth(t)
	if err := p.f.disp.PostBatch(context.Background(), p.ssh); err != nil {
		t.Fatal(err)
	}
	if st := p.f.status(t, p.g); st != "deployed" {
		t.Fatalf("g status = %s", st)
	}
	if st := p.f.status(t, p.g2); st != "pending" || p.cmds() != 1 || p.tails(t) != 1 {
		t.Fatalf("g2 %s cmds %d tails %d", st, p.cmds(), p.tails(t))
	}
}

// A tail another batch job holds is skipped, not waited for or run twice.
func TestPostBatchSkipsLockedTail(t *testing.T) {
	p := newBatchPair(t)
	a := p.sshAction(t, "reload", "post_deploy", "reload-it")
	p.f.setSteps(t, p.g, step(a))
	p.f.setSteps(t, p.g2, step(a))
	p.deployBoth(t)
	ctx := context.Background()
	tx, err := p.f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT 1 FROM server_post_tails WHERE grant_id = $1 FOR UPDATE`, p.g); err != nil {
		t.Fatal(err)
	}
	if err := p.f.disp.PostBatch(ctx, p.ssh); err != nil {
		t.Fatal(err)
	}
	if st := p.f.status(t, p.g); st != "pending" {
		t.Fatalf("locked grant status = %s", st)
	}
	if st := p.f.status(t, p.g2); st != "deployed" || p.cmds() != 1 {
		t.Fatalf("g2 %s cmds %d", st, p.cmds())
	}
	_ = tx.Rollback(ctx)
	if err := p.f.disp.PostBatch(ctx, p.ssh); err != nil {
		t.Fatal(err)
	}
	if st := p.f.status(t, p.g); st != "deployed" || p.cmds() != 2 {
		t.Fatalf("g %s cmds %d", st, p.cmds())
	}
}
