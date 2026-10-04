//go:build integration

package audit_test

import (
	"context"
	"sync"
	"testing"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/db/dbtest"
)

func recordN(t *testing.T, a *audit.Auditor, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := a.Record(context.Background(), audit.Event{Action: "x", ResourceType: "y", Details: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
}

func wantReason(t *testing.T, a *audit.Auditor, reason string) audit.VerifyResult {
	t.Helper()
	r, err := a.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.OK || r.Reason != reason {
		t.Fatalf("want reason %q, got %+v", reason, r)
	}
	return r
}

func TestAnchorDetectsTailTruncation(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	recordN(t, a, 4)
	if r, err := a.Check(ctx); err != nil || !r.OK || r.HeadID != 4 || r.AnchorID != 4 {
		t.Fatalf("clean chain %+v %v", r, err)
	}
	for _, stmt := range []string{
		"ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable",
		"DELETE FROM audit_events WHERE id > 2",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	// The remaining rows still link perfectly; only the anchor can tell.
	r := wantReason(t, a, audit.ReasonTailTruncated)
	if r.BrokenAtID != 3 || r.HeadID != 2 || r.AnchorID != 4 {
		t.Fatalf("truncation %+v", r)
	}
	if _, err := a.Verify(ctx); err == nil {
		t.Fatal("Verify accepted a truncated chain")
	}
}

func TestAnchorDetectsFullTruncation(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	recordN(t, a, 2)
	for _, stmt := range []string{
		"ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable",
		"ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_truncate",
		"DELETE FROM audit_events",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	wantReason(t, a, audit.ReasonTailTruncated)
}

func TestAnchorTamperedMAC(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	recordN(t, a, 2)
	if _, err := pool.Exec(ctx, `UPDATE settings SET value = jsonb_set(value, '{mac}', '"00"') WHERE key = 'audit.head'`); err != nil {
		t.Fatal(err)
	}
	wantReason(t, a, audit.ReasonAnchorInvalid)
	// An anchor written under another key is just as invalid.
	if err := audit.New(pool, append([]byte{1}, testKey[1:]...)).WriteAnchorForTest(ctx, 2, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	wantReason(t, a, audit.ReasonAnchorInvalid)
}

func TestAnchorHashMismatch(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	recordN(t, a, 3)
	if err := a.WriteAnchorForTest(ctx, 3, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if r := wantReason(t, a, audit.ReasonAnchorMismatch); r.BrokenAtID != 3 {
		t.Fatalf("%+v", r)
	}
}

func TestAnchorMissingAndUpgradePath(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	recordN(t, a, 3)
	// An install upgraded from before the anchor existed: keyed rows, no anchor.
	if _, err := pool.Exec(ctx, `DELETE FROM settings WHERE key = 'audit.head'`); err != nil {
		t.Fatal(err)
	}
	wantReason(t, a, audit.ReasonAnchorMissing)
	// Startup Rechain creates it from the current head; the first verify is clean.
	if n, err := a.Rechain(ctx); err != nil || n != 0 {
		t.Fatalf("rechain %d %v", n, err)
	}
	if r, err := a.Check(ctx); err != nil || !r.OK || r.AnchorID != 3 {
		t.Fatalf("after upgrade %+v %v", r, err)
	}
	// A fresh install (no rows, no anchor) is not a failure either.
	pool2, _ := dbtest.New(t)
	if r, err := audit.New(pool2, testKey).Check(ctx); err != nil || !r.OK {
		t.Fatalf("empty %+v %v", r, err)
	}
}

func TestAnchorUpgradeFromLegacyRows(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	insertLegacy(t, pool, a, 3)
	if r, err := a.Check(ctx); err != nil || !r.OK || r.AnchorID != 0 {
		t.Fatalf("legacy chain without anchor must verify: %+v %v", r, err)
	}
	if n, err := a.Rechain(ctx); err != nil || n != 3 {
		t.Fatalf("rechain %d %v", n, err)
	}
	if r, err := a.Check(ctx); err != nil || !r.OK || r.AnchorID != 3 || r.HeadID != 3 {
		t.Fatalf("after rechain %+v %v", r, err)
	}
}

func TestRechainDoesNotReanchorOverTruncation(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	recordN(t, a, 3)
	for _, stmt := range []string{
		"ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable",
		"DELETE FROM audit_events WHERE id = 3",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Rechain(ctx); err != nil {
		t.Fatal(err)
	}
	wantReason(t, a, audit.ReasonTailTruncated)
}

func TestVerifyReasonsForRowFailures(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	recordN(t, a, 2)
	for _, stmt := range []string{
		"ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable",
		`UPDATE audit_events SET details = '{"x":1}' WHERE id = 1`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if r := wantReason(t, a, audit.ReasonRowMismatch); r.BrokenAtID != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestCheckDuringConcurrentRecords(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	recordN(t, a, 3)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		recordN(t, a, 30)
	}()
	for i := 0; i < 15; i++ {
		if r, err := a.Check(ctx); err != nil || !r.OK {
			t.Fatalf("check %d during appends: %+v %v", i, r, err)
		}
	}
	wg.Wait()
	if r, err := a.Check(ctx); err != nil || !r.OK || r.HeadID != 33 || r.AnchorID != 33 {
		t.Fatalf("final %+v %v", r, err)
	}
}
