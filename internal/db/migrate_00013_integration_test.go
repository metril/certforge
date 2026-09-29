//go:build integration

package db_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/metril/certforge/internal/db/dbtest"
)

// TestMigration00013Constraints covers Phase 6A Task 1's migration: an
// unknown event kind, a duplicate dedupe key and a sub-5-minute monitor
// interval are all rejected, and deleting a channel cascades its
// deliveries.
func TestMigration00013Constraints(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	org := dbtest.Org(t, pool)

	var channelID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO notification_channels (org_id, name, type) VALUES ($1, 'c1', 'webhook') RETURNING id`,
		org).Scan(&channelID); err != nil {
		t.Fatal(err)
	}

	// An unknown event kind violates notification_events_kind_check.
	_, err := pool.Exec(ctx,
		`INSERT INTO notification_events (kind, severity, resource_type, summary, dedupe_key)
		 VALUES ('bogus.kind', 'info', 'certificate', 'x', 'dedupe-1')`)
	if pe := pgErr(err); pe == nil || pe.Code != pgCheckViolation {
		t.Fatalf("unknown event kind: err = %v, want CHECK violation (SQLSTATE %s)", err, pgCheckViolation)
	}

	// A duplicate dedupe_key violates the UNIQUE constraint (Emit's no-op path).
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_events (kind, severity, resource_type, summary, dedupe_key)
		 VALUES ('test', 'info', 'channel', 'x', 'dedupe-2')`); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO notification_events (kind, severity, resource_type, summary, dedupe_key)
		 VALUES ('test', 'info', 'channel', 'y', 'dedupe-2')`)
	if pe := pgErr(err); pe == nil || pe.Code != pgUniqueViolation {
		t.Fatalf("duplicate dedupe_key: err = %v, want UNIQUE violation (SQLSTATE %s)", err, pgUniqueViolation)
	}

	// A sub-5-minute interval violates external_monitors_interval_seconds_check.
	_, err = pool.Exec(ctx,
		`INSERT INTO external_monitors (org_id, name, host, interval_seconds) VALUES ($1, 'm1', 'a.example.test', 299)`, org)
	if pe := pgErr(err); pe == nil || pe.Code != pgCheckViolation {
		t.Fatalf("299s interval: err = %v, want CHECK violation (SQLSTATE %s)", err, pgCheckViolation)
	}

	// Deleting a channel cascades its deliveries (notification_deliveries.channel_id ON DELETE CASCADE).
	var eventID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO notification_events (kind, severity, resource_type, summary, dedupe_key)
		 VALUES ('test', 'info', 'channel', 'x', 'dedupe-3') RETURNING id`).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_deliveries (event_id, channel_id) VALUES ($1, $2)`, eventID, channelID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM notification_channels WHERE id = $1`, channelID); err != nil {
		t.Fatalf("delete channel: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM notification_deliveries WHERE channel_id = $1`, channelID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("deliveries after channel delete: %d, want 0 (cascade)", n)
	}
}

// TestEveryForeignKeyDeferrable is the standing test from the pre-flight
// ruling: every non-river, non-goose foreign key in the schema is
// DEFERRABLE INITIALLY IMMEDIATE, so a future restore (Task 10/11) can load
// tables out of dependency order under SET CONSTRAINTS ALL DEFERRED.
func TestEveryForeignKeyDeferrable(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()

	rows, err := pool.Query(ctx, `
		SELECT c.conname, c.conrelid::regclass::text, c.condeferrable, c.condeferred
		FROM pg_constraint c
		JOIN pg_namespace n ON n.oid = c.connamespace
		WHERE c.contype = 'f'
		  AND n.nspname = 'public'
		  AND c.conrelid::regclass::text NOT LIKE 'river_%'
		  AND c.conrelid::regclass::text NOT LIKE 'goose_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	found := 0
	for rows.Next() {
		var conname, tbl string
		var deferrable, deferred bool
		if err := rows.Scan(&conname, &tbl, &deferrable, &deferred); err != nil {
			t.Fatal(err)
		}
		found++
		if !deferrable {
			t.Errorf("%s.%s: not deferrable", tbl, conname)
		}
		if deferred {
			t.Errorf("%s.%s: initially deferred, want initially immediate", tbl, conname)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no foreign keys found to check")
	}
}

// TestMigration00013DownUp proves goose down to 00012 and back up to 00013
// succeeds.
func TestMigration00013DownUp(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Empty(t)
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()

	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up: %v", err)
	}

	var orgID, channelID, eventID string
	if err := pool.QueryRow(ctx, `INSERT INTO orgs (slug, name) VALUES ('t13', 'T13') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO notification_channels (org_id, name, type) VALUES ($1, 'c', 'webhook') RETURNING id`, orgID,
	).Scan(&channelID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO notification_events (kind, severity, resource_type, summary, dedupe_key)
		 VALUES ('test', 'info', 'channel', 'x', 'downup') RETURNING id`).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_deliveries (event_id, channel_id) VALUES ($1, $2)`, eventID, channelID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO external_monitors (org_id, name, host) VALUES ($1, 'm', 'a.example.test')`, orgID); err != nil {
		t.Fatal(err)
	}

	if _, err := p.DownTo(ctx, 12); err != nil {
		t.Fatalf("down to 00012 with ops rows present: %v", err)
	}
	if _, err := p.UpTo(ctx, 13); err != nil {
		t.Fatalf("up to 00013: %v", err)
	}
}
