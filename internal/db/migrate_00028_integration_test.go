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

// TestMigration00028RestartHooks checks restart hooks may have an empty argv
// only with a target, exec hooks keep their argv rule, and down removes
// restart hooks and the columns.
func TestMigration00028RestartHooks(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	org := dbtest.Org(t, pool)
	ins := func(name, kind, target string, argv []string) error {
		_, err := pool.Exec(ctx, `INSERT INTO hooks (org_id, name, phase, argv, kind, target) VALUES ($1, $2, 'post_deploy', $3, $4, $5)`,
			org, name, argv, kind, target)
		return err
	}
	if err := ins("exec", "exec", "", []string{"/bin/true"}); err != nil {
		t.Fatal(err)
	}
	if err := ins("restart", "restart", "docker:nginx", []string{}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		kind, target string
		argv         []string
	}{
		"exec-empty-argv":        {"exec", "", []string{}},
		"restart-with-argv":      {"restart", "docker:x", []string{"/bin/true"}},
		"restart-without-target": {"restart", "", []string{}},
		"bad-kind":               {"reboot", "docker:x", []string{}},
	} {
		if err := ins(name, c.kind, c.target, c.argv); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 27); err != nil {
		t.Fatalf("down to 00027: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM hooks`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("hooks after down: %d, %v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='hooks' AND column_name IN ('kind','target')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("columns after down: %d, %v", n, err)
	}
	if _, err := p.UpTo(ctx, 28); err != nil {
		t.Fatalf("up to 00028: %v", err)
	}
}
