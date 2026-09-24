//go:build integration

package db_test

import (
	"context"
	"testing"

	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/db/dbtest"
)

func TestMigrateCreatesRiverTables(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name IN ('river_job', 'river_leader', 'river_queue')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("river tables = %d, want 3", n)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}
