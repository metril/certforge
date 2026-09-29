//go:build integration

package monitor_test

import (
	"context"
	"testing"
	"time"

	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/monitor"
)

// TestUpdateDoesNotOverwriteConcurrentTransition: a check's own CAS
// transition (TransitionState), committed after Update's caller last read
// the monitor but before Update itself runs, must survive a subsequent
// non-resetting Update untouched (batch-3 review finding 4) — Update's own
// state/state_changed_at/next_check_at columns must come from the row
// Update itself locks, never from a value the caller captured earlier.
func TestUpdateDoesNotOverwriteConcurrentTransition(t *testing.T) {
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	store := &monitor.Store{Pool: pool, Q: sqlcgen.New(pool)}
	ctx := context.Background()

	id := insertMonitor(t, pool, monitorRow{orgID: org, name: "m", host: "old.example.test", state: "ok"})

	// A concurrent check's own CAS transition, "during" the update in the
	// sense that it commits between whenever an API caller last read this
	// monitor and whenever Update itself actually runs.
	transitionAt := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	won, err := store.TransitionState(ctx, monitor.TransitionParams{
		ID: id, OldState: "ok", NewState: "unreachable", StateChangedAt: transitionAt, CheckedAt: transitionAt,
		NextCheckAt: transitionAt.Add(time.Hour), LastFingerprint: "", LastNotAfter: nil, LastIssuer: "", LastError: "refused",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !won {
		t.Fatal("expected the transition to win (no concurrent writer)")
	}

	// A benign update (rename only, resetState false) must leave the
	// transition's state/state_changed_at/next_check_at exactly as they are.
	in := monitor.Input{Name: "m-renamed", Host: "old.example.test", Port: 443, IntervalSeconds: 3600, Enabled: true}
	updated, err := store.Update(ctx, org, id, in, false)
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != "unreachable" {
		t.Fatalf("state after update = %q, want unreachable (the CAS transition must survive)", updated.State)
	}
	if !updated.StateChangedAt.Equal(transitionAt) {
		t.Fatalf("stateChangedAt after update = %v, want unchanged (%v)", updated.StateChangedAt, transitionAt)
	}
	if !updated.NextCheckAt.Equal(transitionAt.Add(time.Hour)) {
		t.Fatalf("nextCheckAt after update = %v, want unchanged (%v)", updated.NextCheckAt, transitionAt.Add(time.Hour))
	}

	// A resetting update (host changes) still resets, on top of the
	// transition.
	in2 := monitor.Input{Name: "m-renamed", Host: "new.example.test", Port: 443, IntervalSeconds: 3600, Enabled: true}
	before := time.Now()
	updated, err = store.Update(ctx, org, id, in2, true)
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != "unknown" {
		t.Fatalf("state after resetting update = %q, want unknown", updated.State)
	}
	if updated.NextCheckAt.Before(before) {
		t.Fatalf("nextCheckAt after resetting update = %v, want >= %v", updated.NextCheckAt, before)
	}
}
