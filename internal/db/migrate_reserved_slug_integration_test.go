//go:build integration

package db_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/metril/certforge/internal/db/dbtest"
)

// TestMigrateRejectsReservedSlug covers migration 00005's DO block (C5): a
// pre-existing org with slug "all" must stop the migration with a clear,
// actionable error naming the org, not a bare constraint violation.
func TestMigrateRejectsReservedSlug(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Empty(t)
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()

	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 4); err != nil {
		t.Fatalf("migrate to 00004: %v", err)
	}
	var orgID string
	if err := pool.QueryRow(ctx, `INSERT INTO orgs (slug, name) VALUES ('all', 'All') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	_, err = p.UpTo(ctx, 5)
	if err == nil {
		t.Fatal("expected migration 00005 to fail with a pre-existing \"all\" org")
	}
	if !strings.Contains(err.Error(), orgID) || !strings.Contains(err.Error(), `reserved slug "all"`) {
		t.Fatalf("error %q does not name the org or explain the reservation", err)
	}
}
