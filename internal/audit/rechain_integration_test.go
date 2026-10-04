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
	// 3 converted rows, the audit.anchor_initialized marker Rechain appended, and "after".
	if r, err := a.Check(ctx); err != nil || !r.OK || r.Count != 5 {
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

// TestCheckRejectsLegacyAfterRechain covers the monotonic downgrade gate
// (controller ruling, fix round 1): once a hmac-sha256 row has been seen in
// chain order, Check and Rechain both reject ANY later sha256-algorithm row
// as broken — even one appended after the chain was re-keyed and internally
// consistent under its own stored algorithm (a downgrade attempt, whether
// from a bug or an attacker with direct DB access) — and Rechain must never
// launder such a row into a freshly-rewritten, valid HMAC row.
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
	// 2 converted rows, the anchor marker, and "after".
	if r, err := a.Check(ctx); err != nil || !r.OK || r.Count != 4 {
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

	// Rechain must refuse too, and must not launder the forged row into a
	// freshly-rewritten valid HMAC row: it stays sha256, unchanged.
	if _, err := a.Rechain(ctx); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("rechain should refuse the forged row: err = %v", err)
	}
	if n, _ := q.CountLegacyAuditEvents(ctx); n != 1 {
		t.Fatalf("forged row was laundered: %d legacy rows left, want 1", n)
	}
}

// TestTriggerRejectsRelabelToLegacy covers fix round 1, item 2: migration
// 00006's append-only trigger allows an UPDATE that touches only hash,
// prev_hash and hash_alg (what Rechain performs), but only when the new
// hash_alg stays hmac-sha256 — it refuses to relabel a row back to sha256
// even via that narrow allowance. A same-shaped update that keeps
// hmac-sha256 is accepted by the trigger (it proves nothing about the hash
// itself), and Check — verifying with the real key — is what actually
// catches the wrong hash it wrote.
func TestTriggerRejectsRelabelToLegacy(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	if err := a.Record(ctx, audit.Event{Action: "x", ResourceType: "y"}); err != nil {
		t.Fatal(err)
	}

	// The trigger rejects a hash-only update that relabels to sha256, even
	// though it touches only the three allowed columns.
	_, err := pool.Exec(ctx, `UPDATE audit_events SET hash = hash, prev_hash = prev_hash, hash_alg = 'sha256' WHERE id = 1`)
	if err == nil {
		t.Fatal("trigger allowed relabelling a row back to sha256")
	}

	// The trigger accepts a hash-only update that keeps hmac-sha256, even
	// with a wrong hash: the trigger is not a proof of integrity by itself.
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET hash = '\x00', prev_hash = prev_hash, hash_alg = 'hmac-sha256' WHERE id = 1`); err != nil {
		t.Fatalf("trigger should have accepted a same-algorithm hash update: %v", err)
	}
	r, err := a.Check(ctx)
	if err != nil || r.OK || r.BrokenAtID != 1 {
		t.Fatalf("check should have caught the wrong hash: %+v %v", r, err)
	}
}

// TestCheckAndRechainFailClosedOnce covers fix round 2: an adversary with
// table-owner access can bypass the append-only trigger entirely and
// replace the *whole* table with a self-consistent, legacy-only sha256
// chain. No hmac-sha256 row is ever reachable in that replacement chain, so
// the monotonic per-row rule (fix round 1) never trips — the audit.chain_keyed
// setting, read up front and checked independently of the per-row walk, is
// what catches it: once the chain has been keyed, Check reports the very
// first row of a legacy-only chain broken, and Rechain refuses to rewrite
// anything (fail closed) rather than treating the replacement as unconverted
// history to re-key.
func TestCheckAndRechainFailClosedOnce(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool, testKey)
	if err := a.Record(ctx, audit.Event{Action: "x", ResourceType: "y"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Rechain(ctx); err != nil {
		t.Fatal(err)
	}
	if r, err := a.Check(ctx); err != nil || !r.OK {
		t.Fatalf("chain before replacement %+v %v", r, err)
	}

	// Replace the entire table with a valid legacy-only chain, as an
	// owner-access adversary could: disable the trigger, delete every row,
	// insert a self-consistent sha256 chain.
	for _, stmt := range []string{
		"ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable",
		"DELETE FROM audit_events",
		"ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	insertLegacy(t, pool, a, 3)

	r, err := a.Check(ctx)
	if err != nil || r.OK || r.BrokenAtID == 0 {
		t.Fatalf("check should fail closed on the replaced legacy chain: %+v %v", r, err)
	}
	first, err := q.ListAuditEventsAsc(ctx, sqlcgen.ListAuditEventsAscParams{ID: 0, Limit: 1})
	if err != nil || len(first) == 0 {
		t.Fatalf("first: %v %v", first, err)
	}
	if r.BrokenAtID != first[0].ID {
		t.Fatalf("broken at %d, want the replacement chain's first row (id %d)", r.BrokenAtID, first[0].ID)
	}

	if _, err := a.Rechain(ctx); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("rechain should refuse the replacement chain: err = %v", err)
	}
	if n, _ := q.CountLegacyAuditEvents(ctx); n != 3 {
		t.Fatalf("replacement chain was rewritten: %d legacy rows left, want 3", n)
	}
}
