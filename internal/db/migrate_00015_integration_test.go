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

// TestMigration00015 covers Phase 7A Task 1's migration: type/runs_on
// agreement for deploy_targets moves out of the database (Deviations R16,
// R3) — the registry, not a fixed CHECK, is authoritative from Task 2 on —
// so any type string now inserts, while the unrelated
// runs_on IN ('agent', 'server') check still holds. secret_cfg stores a
// target secret. goose down to 00014 must delete the now out-of-range
// row before it can restore the two dropped checks, and a subsequent up
// must succeed.
func TestMigration00015(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	org := dbtest.Org(t, pool)

	// A type the pre-00015 CHECK never allowed inserts cleanly now that the
	// registry owns type/runs_on agreement; secret_cfg holds a target
	// secret (a marshalled crypto.Blob in production, an opaque byte
	// string here).
	var targetID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO deploy_targets (org_id, name, type, runs_on, secret_cfg) VALUES ($1, 'test-secret', 'test-secret', 'server', $2) RETURNING id`,
		org, []byte("sealed-secret")).Scan(&targetID); err != nil {
		t.Fatalf("insert with dropped type/runs_on checks: %v", err)
	}

	var storedSecret []byte
	if err := pool.QueryRow(ctx, `SELECT secret_cfg FROM deploy_targets WHERE id = $1`, targetID).Scan(&storedSecret); err != nil {
		t.Fatal(err)
	}
	if string(storedSecret) != "sealed-secret" {
		t.Fatalf("secret_cfg = %q, want %q", storedSecret, "sealed-secret")
	}

	// runs_on IN ('agent', 'server') still holds: it is unrelated to the
	// two dropped type checks.
	_, err := pool.Exec(ctx,
		`INSERT INTO deploy_targets (org_id, name, type, runs_on) VALUES ($1, 'both-target', 'test-secret', 'both')`, org)
	if pe := pgErr(err); pe == nil || pe.Code != pgCheckViolation {
		t.Fatalf("runs_on='both': err = %v, want CHECK violation (SQLSTATE %s)", err, pgCheckViolation)
	}

	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := p.DownTo(ctx, 14); err != nil {
		t.Fatalf("down to 00014 with a non-traefik/vault-kv row present: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM deploy_targets WHERE id = $1`, targetID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("down to 00014 did not delete the row its restored type check cannot satisfy")
	}

	if _, err := p.UpTo(ctx, 15); err != nil {
		t.Fatalf("up to 00015: %v", err)
	}
}
