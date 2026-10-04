//go:build integration

package notify_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/notify"
)

func newEvent(orgID *uuid.UUID, kind, dedupeKey string) notify.Event {
	return notify.Event{
		ID:        uuid.New(),
		Kind:      kind,
		OrgID:     orgID,
		Resource:  notify.Resource{Type: notify.ResourceTypeOf(kind), ID: "r1", Name: "r1"},
		Summary:   "test summary",
		DedupeKey: dedupeKey,
	}
}

func TestEmitDuplicateIsNoop(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	// A matching channel (batch-1 review finding 5): without one, this
	// test could not show that a duplicate Emit adds no delivery row or
	// job, only that it adds no event row.
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}

	ev := newEvent(&org, "cert.issued", "cert.issued:"+uuid.NewString())

	created, err := e.Emit(ctx, nil, ev)
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	if !created {
		t.Fatal("first Emit reported created=false")
	}
	if got := countRows(t, pool, "notification_events", "dedupe_key = $1", ev.DedupeKey); got != 1 {
		t.Fatalf("notification_events rows = %d, want 1", got)
	}
	deliveryWhere := "event_id IN (SELECT id FROM notification_events WHERE dedupe_key = $1)"
	if got := countRows(t, pool, "notification_deliveries", deliveryWhere, ev.DedupeKey); got != 1 {
		t.Fatalf("notification_deliveries rows = %d, want 1", got)
	}
	if got := len(ins.channelIDs()); got != 1 {
		t.Fatalf("River.InsertTx called %d times, want 1", got)
	}

	// A second Emit with the same DedupeKey (a different event ID — Emit
	// generates a fresh id server-side via the events table's default, but
	// this Event's own ID field is client-supplied and irrelevant to the
	// dedupe check, which is on dedupe_key alone) is a silent no-op: no
	// second event row, no second delivery row, no second job.
	created2, err := e.Emit(ctx, nil, ev)
	if err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	if created2 {
		t.Fatal("second Emit reported created=true for a duplicate dedupe_key")
	}
	if got := countRows(t, pool, "notification_events", "dedupe_key = $1", ev.DedupeKey); got != 1 {
		t.Fatalf("notification_events rows after duplicate = %d, want 1", got)
	}
	if got := countRows(t, pool, "notification_deliveries", deliveryWhere, ev.DedupeKey); got != 1 {
		t.Fatalf("notification_deliveries rows after duplicate = %d, want still 1", got)
	}
	if got := len(ins.channelIDs()); got != 1 {
		t.Fatalf("River.InsertTx called %d times after duplicate, want still 1", got)
	}
}

func TestEmitRejectsEmptyDedupeKey(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	e := &notify.Emitter{Pool: pool, River: &fakeInserter{}}

	_, err := e.Emit(ctx, nil, newEvent(&org, "cert.issued", ""))
	if err == nil {
		t.Fatal("Emit accepted an empty DedupeKey")
	}
	if got := countRows(t, pool, "notification_events", "org_id = $1", org); got != 0 {
		t.Fatalf("notification_events rows = %d, want 0 (rejected before insert)", got)
	}
}

func TestEmitFixesResourceTypeToKind(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	e := &notify.Emitter{Pool: pool, River: &fakeInserter{}}

	// A caller-supplied Resource.Type that doesn't match the kind's own
	// fixed resource type (ADR 0017) is silently corrected, not trusted.
	ev := newEvent(&org, "cert.issued", "cert.issued:"+uuid.NewString())
	ev.Resource.Type = "monitor"

	if _, err := e.Emit(ctx, nil, ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	var resourceType string
	if err := pool.QueryRow(ctx, "SELECT resource_type FROM notification_events WHERE dedupe_key = $1", ev.DedupeKey).Scan(&resourceType); err != nil {
		t.Fatalf("query resource_type: %v", err)
	}
	if resourceType != "certificate" {
		t.Errorf("resource_type = %q, want %q (cert.issued's own fixed type, not the caller's)", resourceType, "certificate")
	}
}

func TestEmitMatchesChannels(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	orgA := dbtest.Org(t, pool)
	orgB := dbtest.Org(t, pool)

	allEvents := insertChannel(t, pool, testChannel{orgID: orgA, name: "all-events"})
	certOnly := insertChannel(t, pool, testChannel{orgID: orgA, name: "cert-only", events: []string{"cert.issued"}})
	disabledFalse := false
	disabled := insertChannel(t, pool, testChannel{orgID: orgA, name: "disabled", enabled: &disabledFalse})
	allOrgs := insertChannel(t, pool, testChannel{orgID: orgB, name: "all-orgs", allOrgs: true})
	otherOrg := insertChannel(t, pool, testChannel{orgID: orgB, name: "other-org"})
	highSeverity := insertChannel(t, pool, testChannel{orgID: orgA, name: "critical-only", minSeverity: "critical"})

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}

	// cert.renewal_failed is "warning" severity (TestKindsAndSeverities).
	ev := newEvent(&orgA, "cert.renewal_failed", "cert.renewal_failed:"+uuid.NewString())
	created, err := e.Emit(ctx, nil, ev)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !created {
		t.Fatal("Emit reported created=false")
	}

	got := ins.channelIDs()
	want := map[uuid.UUID]bool{allEvents: true, allOrgs: true}
	if len(got) != len(want) {
		t.Fatalf("matched channels = %v, want exactly %v", got, want)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected match %v", id)
		}
	}
	unwanted := map[string]uuid.UUID{"certOnly": certOnly, "disabled": disabled, "otherOrg": otherOrg, "highSeverity": highSeverity}
	matched := map[uuid.UUID]bool{}
	for _, id := range got {
		matched[id] = true
	}
	for name, id := range unwanted {
		if matched[id] {
			t.Errorf("%s channel should not have matched", name)
		}
	}
}

func TestEmitGlobalEventMatchesAllOrgsOnly(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	orgA := dbtest.Org(t, pool)

	orgScoped := insertChannel(t, pool, testChannel{orgID: orgA, name: "org-scoped"})
	allOrgs := insertChannel(t, pool, testChannel{orgID: orgA, name: "all-orgs-2", allOrgs: true})

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}

	// backup.completed is a global kind (orgId null).
	ev := newEvent(nil, "backup.completed", "backup.completed:"+uuid.NewString())
	if _, err := e.Emit(ctx, nil, ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	got := ins.channelIDs()
	if len(got) != 1 || got[0] != allOrgs {
		t.Fatalf("matched channels = %v, want exactly [%v] (all_orgs only)", got, allOrgs)
	}
	if got[0] == orgScoped {
		t.Fatal("org-scoped channel matched a global event")
	}
}

func TestEmitUnknownKindErrors(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	e := &notify.Emitter{Pool: pool, River: &fakeInserter{}}

	_, err := e.Emit(ctx, nil, newEvent(&org, "bogus.kind", "bogus:1"))
	if err == nil {
		t.Fatal("Emit accepted an unknown kind")
	}
}

func TestEmitInsideCallerTx(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	dedupeKey := "cert.issued:" + uuid.NewString()
	ev := newEvent(&org, "cert.issued", dedupeKey)

	created, err := e.Emit(ctx, tx, ev)
	if err != nil {
		t.Fatalf("Emit inside caller tx: %v", err)
	}
	if !created {
		t.Fatal("Emit reported created=false")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	if got := countRows(t, pool, "notification_events", "dedupe_key = $1", dedupeKey); got != 0 {
		t.Fatalf("notification_events rows after rollback = %d, want 0", got)
	}
	if got := countRows(t, pool, "notification_deliveries", "event_id IN (SELECT id FROM notification_events WHERE dedupe_key = $1)", dedupeKey); got != 0 {
		t.Fatalf("notification_deliveries rows after rollback = %d, want 0", got)
	}
}

func TestEmitSummaryTruncated(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	e := &notify.Emitter{Pool: pool, River: &fakeInserter{}}

	long := make([]byte, 600)
	for i := range long {
		long[i] = 'x'
	}
	ev := newEvent(&org, "cert.issued", "cert.issued:"+uuid.NewString())
	ev.Summary = string(long)

	if _, err := e.Emit(ctx, nil, ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	var summary string
	if err := pool.QueryRow(ctx, "SELECT summary FROM notification_events WHERE dedupe_key = $1", ev.DedupeKey).Scan(&summary); err != nil {
		t.Fatalf("query summary: %v", err)
	}
	if len(summary) != 500 {
		t.Errorf("stored summary length = %d, want 500", len(summary))
	}
}

// matchTracer counts the channel-match queries a pool runs.
type matchTracer struct{ n atomic.Int32 }

func (m *matchTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "notification_channels") && strings.Contains(d.SQL, "all_orgs") {
		m.n.Add(1)
	}
	return ctx
}

func (m *matchTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// TestEmitBatch (fix round 2, P6): a duplicate dedupe key is a no-op like
// Emit; an invalid event and a database-rejected event (a NUL byte in the
// summary, which Postgres refuses mid-chunk) fail alone while every other
// event in the chunk commits with its delivery and job; and the channel
// match runs once per (org, kind, severity), not once per event.
func TestEmitBatch(t *testing.T) {
	ctx := context.Background()
	base, _ := dbtest.New(t)
	org := dbtest.Org(t, base)
	insertChannel(t, base, testChannel{orgID: org, name: "all-events"})

	cfg, err := pgxpool.ParseConfig(base.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	tr := &matchTracer{}
	cfg.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	ins := &fakeInserter{}
	e := &notify.Emitter{Pool: pool, River: ins}
	key := func(s string) string { return s + ":" + uuid.NewString() }
	a, b, c := newEvent(&org, "cert.issued", key("a")), newEvent(&org, "cert.issued", key("b")), newEvent(&org, "cert.issued", key("c"))
	nul := newEvent(&org, "cert.issued", key("nul"))
	nul.Summary = "bad\x00summary"
	empty := newEvent(&org, "cert.issued", "")
	evs := []notify.Event{a, a, empty, b, nul, c}

	created, err := e.EmitBatch(ctx, evs)
	if err == nil {
		t.Fatal("want the joined errors of the invalid and rejected events")
	}
	if created != 3 {
		t.Fatalf("created = %d, want 3 (a, b, c)", created)
	}
	for _, ev := range []notify.Event{a, b, c} {
		if got := countRows(t, pool, "notification_events", "dedupe_key = $1", ev.DedupeKey); got != 1 {
			t.Fatalf("%s: event rows = %d, want 1", ev.DedupeKey, got)
		}
	}
	if got := countRows(t, pool, "notification_events", "dedupe_key = $1", nul.DedupeKey); got != 0 {
		t.Fatalf("rejected event left %d rows", got)
	}
	if got := countRows(t, pool, "notification_deliveries", "TRUE"); got != 3 {
		t.Fatalf("deliveries = %d, want 3", got)
	}
	if got := len(ins.channelIDs()); got != 3 {
		t.Fatalf("jobs enqueued = %d, want 3", got)
	}
	if got := tr.n.Load(); got != 1 {
		t.Fatalf("channel match ran %d times for one (org, kind, severity), want 1", got)
	}
}
