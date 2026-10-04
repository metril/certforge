//go:build integration

package monitor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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
