//go:build integration

package monitor_test

import (
	"context"
	"sync"
	"testing"
	"time"

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

// TestMonitorTransitionEmitsOnce: two concurrent checks of the same
// monitor, both observing the same resulting state (unreachable), emit
// exactly one event — the R5 compare-and-set (Deviations R5, Task 9
// brief).
func TestMonitorTransitionEmitsOnce(t *testing.T) {
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	ins := &fakeNotifyInserter{}
	svc := newService(pool, ins)
	allowLoopback(t, svc.Settings)

	port := closedPort(t)
	id := insertMonitor(t, pool, monitorRow{orgID: org, name: "flaky", host: "127.0.0.1", port: port, state: "ok"})

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
// within InlineTimeout (checkMonitor's own 15s bound).
func TestCheckMonitorInline(t *testing.T) {
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	ins := &fakeNotifyInserter{}
	svc := newService(pool, ins)
	allowLoopback(t, svc.Settings)

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	leafDER, key := selfSignedCert(t, "inline.example.test", notAfter)
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
