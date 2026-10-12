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

// TestMigration00029PostAction checks a server hook run may have no client,
// grants default to an empty post action, and down removes server runs and
// the added columns.
func TestMigration00029PostAction(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	org := dbtest.Org(t, pool)
	var tgt string
	if err := pool.QueryRow(ctx, `INSERT INTO deploy_targets (org_id, name, type, runs_on, config) VALUES ($1, 'ssh', 'ssh', 'server', '{}') RETURNING id`, org).Scan(&tgt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO hook_runs (client_id, deploy_target_id, phase, exit_code) VALUES (NULL, $1, 'post_deploy', 0)`, tgt); err != nil {
		t.Fatalf("server run: %v", err)
	}
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 28); err != nil {
		t.Fatalf("down to 00028: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM hook_runs`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("hook_runs after down: %d, %v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE (table_name='client_cert_grants' AND column_name='post_action') OR (table_name='hook_runs' AND column_name='deploy_target_id')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("columns after down: %d, %v", n, err)
	}
	if _, err := p.UpTo(ctx, 29); err != nil {
		t.Fatalf("up to 00029: %v", err)
	}
}
