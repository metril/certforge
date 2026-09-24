//go:build integration

package audit_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func TestRecordAndVerify(t *testing.T) {
	pool, q := dbtest.New(t)
	a := audit.New(pool)
	uid := uuid.New()
	ctx := audit.WithIP(context.Background(), "192.0.2.1")
	ctx = authn.WithPrincipal(ctx, authn.Principal{Kind: authn.KindUser, UserID: uid})
	details := []map[string]any{
		{"section": "general"},
		{"nested": map[string]any{"b": 1.5, "a": "<b>&"}},
		nil,
	}
	for _, d := range details {
		if err := a.Record(ctx, audit.Event{Action: "settings.update", ResourceType: "settings", ResourceID: "general", Details: d}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := a.Verify(ctx); err != nil || n != 3 {
		t.Fatalf("verify n=%d err=%v", n, err)
	}
	evs, err := q.ListAuditEventsAsc(ctx, sqlcgen.ListAuditEventsAscParams{ID: 0, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(evs[0].PrevHash, make([]byte, 32)) || !bytes.Equal(evs[1].PrevHash, evs[0].Hash) {
		t.Fatal("chain links wrong")
	}
	if evs[0].ActorType != "user" || evs[0].ActorID != uid.String() || evs[0].Ip != "192.0.2.1" {
		t.Fatalf("actor %+v", evs[0])
	}
}

func TestSystemActor(t *testing.T) {
	pool, q := dbtest.New(t)
	ctx := context.Background()
	if err := audit.New(pool).Record(ctx, audit.Event{Action: "x", ResourceType: "y"}); err != nil {
		t.Fatal(err)
	}
	evs, _ := q.ListAuditEventsAsc(ctx, sqlcgen.ListAuditEventsAscParams{ID: 0, Limit: 1})
	if evs[0].ActorType != "system" {
		t.Fatalf("actor type %q", evs[0].ActorType)
	}
}

func TestAppendOnly(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	if err := audit.New(pool).Record(ctx, audit.Event{Action: "x", ResourceType: "y"}); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{"UPDATE audit_events SET action = 'z'", "DELETE FROM audit_events", "TRUNCATE audit_events"} {
		_, err := pool.Exec(ctx, stmt)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: err = %v", stmt, err)
		}
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool)
	for i := 0; i < 2; i++ {
		if err := a.Record(ctx, audit.Event{Action: "x", ResourceType: "y", Details: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, stmt := range []string{
		"ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable",
		`UPDATE audit_events SET details = '{"tampered": true}' WHERE id = (SELECT min(id) FROM audit_events)`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Verify(ctx); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyDetectsDeletedRow(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool)
	for i := 0; i < 3; i++ {
		if err := a.Record(ctx, audit.Event{Action: "x", ResourceType: "y", Details: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, stmt := range []string{
		"ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable",
		"DELETE FROM audit_events WHERE id = (SELECT id FROM audit_events ORDER BY id LIMIT 1 OFFSET 1)",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Verify(ctx); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("err = %v", err)
	}
}

func TestConcurrentRecords(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	a := audit.New(pool)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- a.Record(ctx, audit.Event{Action: "x", ResourceType: "y", Details: map[string]any{"i": i}})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n, err := a.Verify(ctx); err != nil || n != 20 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}
