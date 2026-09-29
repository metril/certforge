//go:build integration

package notify_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/notify"
)

// fakeInserter is notify.Inserter backed by memory: Emitter's own
// transaction semantics (Emit opens/commits its own tx, or uses the
// caller's) are exercised against the real Postgres rows it writes
// (notification_events/notification_deliveries); the job insert itself
// only needs to be observed here, the way kek.Inserter/deploy.Inserter are
// faked in their own package's tests.
type fakeInserter struct {
	mu    sync.Mutex
	calls []notify.DeliverArgs
}

func (f *fakeInserter) InsertTx(_ context.Context, _ pgx.Tx, args river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	da, ok := args.(notify.DeliverArgs)
	if !ok {
		return nil, fmt.Errorf("notify test: unexpected job args %T", args)
	}
	f.calls = append(f.calls, da)
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}}, nil
}

func (f *fakeInserter) channelIDs() []uuid.UUID {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]uuid.UUID, len(f.calls))
	for i, c := range f.calls {
		out[i] = c.ChannelID
	}
	return out
}

// first returns the sole recorded DeliverArgs call, failing t if there is
// not exactly one.
func (f *fakeInserter) first(t *testing.T) notify.DeliverArgs {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 1 {
		t.Fatalf("fakeInserter recorded %d calls, want exactly 1", len(f.calls))
	}
	return f.calls[0]
}

// testChannel is the shape insertChannel needs; zero values give a
// sensible default (enabled, matches every event and severity, org-scoped
// not all-orgs).
type testChannel struct {
	orgID       uuid.UUID
	name        string
	typ         string
	events      []string
	minSeverity string
	allOrgs     bool
	enabled     *bool // nil means true
	secretCfg   []byte
}

// insertChannel inserts a notification_channels row directly (Task 3 has
// no channel-CRUD queries yet; those land in Task 6's channels.go) and
// returns its id.
func insertChannel(t *testing.T, pool *pgxpool.Pool, c testChannel) uuid.UUID {
	t.Helper()
	if c.name == "" {
		c.name = "channel-" + uuid.NewString()[:8]
	}
	if c.typ == "" {
		c.typ = "webhook"
	}
	if c.minSeverity == "" {
		c.minSeverity = "info"
	}
	enabled := true
	if c.enabled != nil {
		enabled = *c.enabled
	}
	if c.events == nil {
		c.events = []string{}
	}
	var id uuid.UUID
	err := pool.QueryRow(context.Background(), `
		INSERT INTO notification_channels (org_id, name, type, config, secret_cfg, events, min_severity, all_orgs, enabled)
		VALUES ($1, $2, $3, '{}', $4, $5, $6, $7, $8)
		RETURNING id`,
		c.orgID, c.name, c.typ, c.secretCfg, c.events, c.minSeverity, c.allOrgs, enabled,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert channel: %v", err)
	}
	return id
}

func countRows(t *testing.T, pool *pgxpool.Pool, table, where string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table+" WHERE "+where, args...).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}
