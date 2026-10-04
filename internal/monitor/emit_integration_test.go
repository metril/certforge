//go:build integration

package monitor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/monitor"
	"github.com/metril/certforge/internal/notify"
)

// failingInserter makes every delivery-job insert fail, so Emit fails.
type failingInserter struct{}

func (failingInserter) InsertTx(context.Context, pgx.Tx, river.JobArgs, *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	return nil, errors.New("insert refused")
}

// TestFailedEmitRollsBackTransition: a transition whose event cannot be
// emitted is not committed, so the next check retries both.
func TestFailedEmitRollsBackTransition(t *testing.T) {
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	svc := newService(pool, failingInserter{})
	allowLoopback(t, svc.Settings)
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO notification_channels (org_id, name, type, config, events, min_severity, all_orgs, enabled)
		VALUES ($1, 'c', 'webhook', '{}', '{}', 'info', false, true)`, org); err != nil {
		t.Fatal(err)
	}
	id := insertMonitor(t, pool, monitorRow{orgID: org, name: "m", host: "unused.invalid", state: "unknown"})
	// Reachable leaf unknown to the org: unknown -> mismatch.
	svc.Dial = func(string, int, string, bool) monitor.Observation {
		return monitor.Observation{Fingerprint: "ff", NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	}
	if _, err := svc.Check(context.Background(), id); err == nil {
		t.Fatal("Check succeeded despite a failed emit")
	}
	if got := getMonitorState(t, pool, id); got != "unknown" {
		t.Fatalf("state = %q, want unknown (rolled back)", got)
	}
	if got := eventCount(t, pool, "monitor.mismatch"); got != 0 {
		t.Fatalf("events = %d, want 0", got)
	}

	svc.Emitter = &notify.Emitter{Pool: pool, River: &fakeNotifyInserter{}}
	if _, err := svc.Check(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if got := getMonitorState(t, pool, id); got != "mismatch" {
		t.Fatalf("state = %q, want mismatch", got)
	}
	if got := eventCount(t, pool, "monitor.mismatch"); got != 1 {
		t.Fatalf("events = %d, want 1", got)
	}
}

func failingDial(string, int, string, bool) monitor.Observation {
	return monitor.Observation{Err: errors.New("simulated: connection refused")}
}

func failures(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT consecutive_failures FROM external_monitors WHERE id = $1", id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSingleFailureKeepsState: one failed check records the error but keeps
// the state and raises nothing; a success resets the counter, so a flapping
// host never reaches unreachable.
func TestSingleFailureKeepsState(t *testing.T) {
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	svc := newService(pool, &fakeNotifyInserter{})
	allowLoopback(t, svc.Settings)
	fp := "aa"
	insertCertWithFingerprint(t, pool, org, "c", fp, time.Now().Add(90*24*time.Hour))
	id := insertMonitor(t, pool, monitorRow{orgID: org, host: "unused.invalid", state: "ok"})
	good := func(string, int, string, bool) monitor.Observation {
		return monitor.Observation{Fingerprint: fp, NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	}
	for i := 0; i < 3; i++ {
		svc.Dial = failingDial
		m, err := svc.Check(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if m.State != "ok" || m.LastError == "" || failures(t, pool, id) != 1 {
			t.Fatalf("after one failure: state %q lastError %q failures %d", m.State, m.LastError, failures(t, pool, id))
		}
		svc.Dial = good
		if _, err := svc.Check(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		if failures(t, pool, id) != 0 {
			t.Fatal("success did not reset the failure counter")
		}
	}
	if got := eventCount(t, pool, "monitor.unreachable"); got != 0 {
		t.Fatalf("unreachable events = %d, want 0", got)
	}
}

// TestTwoFailuresGoUnreachable: a real outage goes unreachable on the second
// consecutive failure with exactly one event.
func TestTwoFailuresGoUnreachable(t *testing.T) {
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	svc := newService(pool, &fakeNotifyInserter{})
	allowLoopback(t, svc.Settings)
	svc.Dial = failingDial
	id := insertMonitor(t, pool, monitorRow{orgID: org, host: "unused.invalid", state: "ok"})
	for i, want := range []string{"ok", "unreachable", "unreachable"} {
		if _, err := svc.Check(context.Background(), id); err != nil {
			t.Fatal(err)
		}
		if got := getMonitorState(t, pool, id); got != want {
			t.Fatalf("check %d: state %q, want %q", i+1, got, want)
		}
	}
	if got := eventCount(t, pool, "monitor.unreachable"); got != 1 {
		t.Fatalf("unreachable events = %d, want 1", got)
	}
}
