//go:build integration

package api

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/monitor"
	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/settings"
)

// fakeMonitorEventInserter is notify.Inserter backed by memory, the same
// shape internal/notify's own tests use (Emitter needs a river.Inserter
// even when a test never expects a delivery job).
type fakeMonitorEventInserter struct {
	mu    sync.Mutex
	calls int
}

func (f *fakeMonitorEventInserter) InsertTx(_ context.Context, _ pgx.Tx, _ river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}}, nil
}

// monitorFixture is Task 9's own apiFixture: a Server whose Deps.Monitors
// is a real monitor.Service against a live Postgres, separate from
// notifyFixture since checking a monitor needs no notifier registry.
type monitorFixture struct {
	srv      *Server
	pool     *pgxpool.Pool
	q        *sqlcgen.Queries
	org      uuid.UUID
	settings *settings.Store
}

func newMonitorFixture(t *testing.T) *monitorFixture {
	t.Helper()
	pool, q := dbtest.New(t)
	box := cryptotest.PrefixBox{}
	key := bytes.Repeat([]byte{9}, 32)
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(key), key))
	settingsStore := settings.NewStore(q, env)
	aud := audit.New(pool, bytes.Repeat([]byte{6}, 32))

	monSvc := &monitor.Service{
		Store:    &monitor.Store{Pool: pool, Q: q},
		Emitter:  &notify.Emitter{Pool: pool, River: &fakeMonitorEventInserter{}},
		Settings: settingsStore,
	}
	srv := &Server{d: Deps{Log: slog.Default(), Pool: pool, Queries: q, Auditor: aud, Monitors: monSvc,
		Settings: settingsStore, Box: box}}
	return &monitorFixture{srv: srv, pool: pool, q: q, org: dbtest.Org(t, pool), settings: settingsStore}
}

// as returns a context for a user holding role in the fixture org (same
// pattern as notifyFixture.as).
func (f *monitorFixture) as(role string) context.Context {
	b := authn.Binding{Role: role, OrgID: &f.org}
	if role == authz.RoleAdmin {
		b.OrgID = nil
	}
	return authn.WithPrincipal(context.Background(), authn.Principal{Kind: authn.KindUser, UserID: uuid.New(),
		Roles: []string{role}, Bindings: []authn.Binding{b}, OrgIDs: []uuid.UUID{f.org}})
}

func (f *monitorFixture) auditCount(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
