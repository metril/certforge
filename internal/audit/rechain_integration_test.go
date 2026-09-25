//go:build integration

package audit_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

var testKey = bytes.Repeat([]byte{5}, 32)

// insertLegacy writes n Phase 1 style rows (plain SHA-256 links).
func insertLegacy(t *testing.T, pool *pgxpool.Pool, a *audit.Auditor, n int) {
	t.Helper()
	ctx := context.Background()
	q := sqlcgen.New(pool)
	prev := make([]byte, 32)
	for i := 0; i < n; i++ {
		ts := time.Now().UTC().Truncate(time.Microsecond)
		details := []byte(fmt.Sprintf(`{"i":%d}`, i))
		h := a.SumForTest(audit.HashAlgLegacy, prev, ts, "system", "", "legacy", "x", "", nil, "", details)
		if _, err := q.InsertAuditEvent(ctx, sqlcgen.InsertAuditEventParams{Ts: ts, ActorType: "system", Action: "legacy",
			ResourceType: "x", Details: details, PrevHash: prev, Hash: h, HashAlg: audit.HashAlgLegacy}); err != nil {
			t.Fatal(err)
		}
		prev = h
	}
}

func TestRechain(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	insertLegacy(t, pool, a, 3)
	if r, err := a.Check(ctx); err != nil || !r.OK || r.Count != 3 {
		t.Fatalf("legacy chain %+v %v", r, err)
	}
	if n, err := a.Rechain(ctx); err != nil || n != 3 {
		t.Fatalf("rechain %d %v", n, err)
	}
	if n, _ := q.CountLegacyAuditEvents(ctx); n != 0 {
		t.Fatalf("%d legacy rows left", n)
	}
	if err := a.Record(ctx, audit.Event{Action: "after", ResourceType: "x"}); err != nil {
		t.Fatal(err)
	}
	if r, err := a.Check(ctx); err != nil || !r.OK || r.Count != 4 {
		t.Fatalf("after rechain %+v %v", r, err)
	}
	if n, err := a.Rechain(ctx); err != nil || n != 0 {
		t.Fatalf("second rechain %d %v", n, err)
	}
	if r, _ := audit.New(pool, bytes.Repeat([]byte{6}, 32)).Check(ctx); r.OK {
		t.Fatal("chain verifies under a different key")
	}
	if _, err := pool.Exec(ctx, "UPDATE audit_events SET action = 'x' WHERE id = 1"); err == nil {
		t.Fatal("append-only trigger left disabled")
	}
}

func TestRechainRefusesTamperedLegacyChain(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	insertLegacy(t, pool, a, 3)
	for _, stmt := range []string{
		"ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable",
		`UPDATE audit_events SET details = '{"i": 99}' WHERE id = (SELECT min(id) + 1 FROM audit_events)`,
		"ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Rechain(ctx); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("err = %v", err)
	}
	if n, _ := q.CountLegacyAuditEvents(ctx); n != 3 {
		t.Fatalf("tampered chain was re-keyed: %d legacy rows", n)
	}
	r, err := a.Check(ctx)
	if err != nil || r.OK || r.BrokenAtID == 0 {
		t.Fatalf("check %+v %v", r, err)
	}
}

// TestCheckRejectsLegacyAfterRechain covers controller ruling C1: once
// Rechain has run and chainKeyedSettingKey is set, Check rejects ANY
// sha256-algorithm row as broken, even one appended after the chain was
// re-keyed (a downgrade attempt, whether from a bug or an attacker with
// direct DB access), not just rows predating the re-chain.
func TestCheckRejectsLegacyAfterRechain(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	insertLegacy(t, pool, a, 2)
	if _, err := a.Rechain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Record(ctx, audit.Event{Action: "after", ResourceType: "x"}); err != nil {
		t.Fatal(err)
	}
	if r, err := a.Check(ctx); err != nil || !r.OK || r.Count != 3 {
		t.Fatalf("chain after rechain %+v %v", r, err)
	}

	// Insert a legacy-algorithm row after re-keying, correctly chained to
	// the current head, simulating a downgrade.
	last, err := q.LastAuditHash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().UTC().Truncate(time.Microsecond)
	details := []byte(`{}`)
	h := a.SumForTest(audit.HashAlgLegacy, last, ts, "system", "", "downgrade", "x", "", nil, "", details)
	if _, err := q.InsertAuditEvent(ctx, sqlcgen.InsertAuditEventParams{Ts: ts, ActorType: "system", Action: "downgrade",
		ResourceType: "x", Details: details, PrevHash: last, Hash: h, HashAlg: audit.HashAlgLegacy}); err != nil {
		t.Fatal(err)
	}

	r, err := a.Check(ctx)
	if err != nil || r.OK || r.BrokenAtID == 0 {
		t.Fatalf("check should reject the legacy row: %+v %v", r, err)
	}
}
