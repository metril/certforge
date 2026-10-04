//go:build integration

package monitor_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/monitor"
)

// TestScanEnqueuesDueOnly: EnqueueDueChecks enqueues an enabled, due
// monitor, but not a not-yet-due one or a disabled one.
func TestScanEnqueuesDueOnly(t *testing.T) {
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	store := &monitor.Store{Pool: pool, Q: sqlcgen.New(pool)}

	due := insertMonitor(t, pool, monitorRow{orgID: org, name: "due", host: "example.test", nextCheckAt: time.Now().Add(-time.Second)})
	insertMonitor(t, pool, monitorRow{orgID: org, name: "not-due", host: "example.test", nextCheckAt: time.Now().Add(time.Hour)})
	disabledOff := false
	insertMonitor(t, pool, monitorRow{orgID: org, name: "disabled", host: "example.test",
		nextCheckAt: time.Now().Add(-time.Second), enabled: &disabledOff})

	ins := &fakeMonitorInserter{}
	n, err := monitor.EnqueueDueChecks(context.Background(), store, ins, 500)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("enqueued = %d, want 1", n)
	}
	ids := ins.ids()
	if len(ids) != 1 || ids[0] != due {
		t.Fatalf("ids = %v, want [%v]", ids, due)
	}
}

// TestScanCountsOnlyNewJobs: InsertMany reports a monitor already queued as
// a unique-skipped duplicate; EnqueueDueChecks counts only the new jobs.
func TestScanCountsOnlyNewJobs(t *testing.T) {
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	store := &monitor.Store{Pool: pool, Q: sqlcgen.New(pool)}
	past := time.Now().Add(-time.Second)
	a := insertMonitor(t, pool, monitorRow{orgID: org, name: "a", host: "example.test", nextCheckAt: past})
	insertMonitor(t, pool, monitorRow{orgID: org, name: "b", host: "example.test", nextCheckAt: past})
	insertMonitor(t, pool, monitorRow{orgID: org, name: "c", host: "example.test", nextCheckAt: past})

	ins := &fakeMonitorInserter{dup: map[uuid.UUID]bool{a: true}}
	n, err := monitor.EnqueueDueChecks(context.Background(), store, ins, 500)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(ins.ids()) != 3 {
		t.Fatalf("enqueued = %d of %d submitted, want 2 of 3", n, len(ins.ids()))
	}
}

// TestCheckWorkerSkipsMissingAndDisabled (A11): a queued check for a
// deleted monitor returns nil (no retry), and one for a monitor disabled
// since it was queued is not run.
func TestCheckWorkerSkipsMissingAndDisabled(t *testing.T) {
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	off := false
	disabled := insertMonitor(t, pool, monitorRow{orgID: org, name: "off", host: "example.test", enabled: &off})
	svc := newService(pool, &fakeNotifyInserter{})
	svc.Dial = func(string, int, string, bool) monitor.Observation {
		t.Error("Dial called for a missing or disabled monitor")
		return monitor.Observation{}
	}
	w := &monitor.CheckWorker{S: svc}
	for name, id := range map[string]uuid.UUID{"missing": uuid.New(), "disabled": disabled} {
		job := &river.Job[monitor.CheckArgs]{Args: monitor.CheckArgs{MonitorID: id}}
		if err := w.Work(context.Background(), job); err != nil {
			t.Fatalf("%s: Work = %v, want nil", name, err)
		}
	}
}

// TestMonitorTransitionEmitsOnce: two checks of the same monitor that
// genuinely overlap — both must read state "ok" before either can write —
// and both observe the same resulting state (unreachable) emit exactly one
// event: the R5 compare-and-set, not a coincidence of Emit's own dedupe key
// (Deviations R5, Task 9 brief; batch-3 review finding 5). Dial is
// overridden with a barrier that only releases once both goroutines have
// reached it — placed after Service.Check's own GetByID, so both are
// guaranteed to have read the same pre-transition row — and Now is
// overridden to hand each call a distinct second, so a same-second Emit
// dedupe key could not itself be what collapses this to one event: if the
// CAS in TransitionState did not exist, both calls would still reach
// Emit, each with its own state_changed_at second, and Emit would insert
// two rows.
func TestMonitorTransitionEmitsOnce(t *testing.T) {
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	ins := &fakeNotifyInserter{}
	svc := newService(pool, ins)
	allowLoopback(t, svc.Settings)

	id := insertMonitor(t, pool, monitorRow{orgID: org, name: "flaky", host: "unused.invalid", state: "ok"})

	var atBarrier sync.WaitGroup
	atBarrier.Add(2)
	release := make(chan struct{})
	svc.Dial = func(string, int, string, bool) monitor.Observation {
		atBarrier.Done()
		<-release
		return monitor.Observation{Err: errors.New("simulated: connection refused")}
	}
	var tick int64
	base := time.Now()
	svc.Now = func() time.Time {
		n := atomic.AddInt64(&tick, 1)
		return base.Add(time.Duration(n) * time.Second) // a distinct second per call
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			if _, err := svc.Check(context.Background(), id); err != nil {
				errs <- err
			}
		}()
	}
	go func() {
		atBarrier.Wait()
		close(release)
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Check: %v", err)
	}

	if got := getMonitorState(t, pool, id); got != "unreachable" {
		t.Fatalf("state = %q, want unreachable", got)
	}
	if got := eventCount(t, pool, "monitor.unreachable"); got != 1 {
		t.Fatalf("monitor.unreachable events = %d, want 1", got)
	}
}

// TestCheckMonitorInline: a single check against a reachable TLS fixture
// with no expected certificate and a far notAfter resolves to ok, well
// within InlineTimeout (checkMonitor's own 15s bound). With no
// expectedCertificateId, "ok" needs the observed leaf's fingerprint to
// match some certificate's current version in the org (batch-3 review
// finding 1), so the fixture's own certificate is seeded as one first.
func TestCheckMonitorInline(t *testing.T) {
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	ins := &fakeNotifyInserter{}
	svc := newService(pool, ins)
	allowLoopback(t, svc.Settings)

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	leafDER, key := selfSignedCert(t, "inline.example.test", notAfter)
	fp := sha256.Sum256(leafDER)
	insertCertWithFingerprint(t, pool, org, "inline-cert", hex.EncodeToString(fp[:]), notAfter)
	port := listenTLS(t, leafDER, key)
	id := insertMonitor(t, pool, monitorRow{orgID: org, name: "inline", host: "127.0.0.1", port: port,
		sni: strPtr("inline.example.test"), state: "unknown"})

	ctx, cancel := context.WithTimeout(context.Background(), monitor.InlineTimeout)
	defer cancel()
	start := time.Now()
	m, err := svc.Check(ctx, id)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if elapsed := time.Since(start); elapsed > monitor.InlineTimeout {
		t.Fatalf("Check took %v, want under InlineTimeout (%v)", elapsed, monitor.InlineTimeout)
	}
	if m.State != "ok" {
		t.Fatalf("state = %q, want ok", m.State)
	}
	if m.LastFingerprint == "" {
		t.Error("lastFingerprint not recorded")
	}
	if got := eventCount(t, pool, "monitor.recovered"); got != 0 {
		t.Errorf("monitor.recovered events = %d, want 0 (unknown -> ok is not a recovery)", got)
	}
}

func strPtr(s string) *string { return &s }
