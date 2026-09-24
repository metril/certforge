//go:build integration

package db_test

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func TestMigrateIdempotent(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	v1, err := db.Version(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if v1 < 1 {
		t.Fatalf("version %d", v1)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	v2, err := db.Version(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if v1 != v2 {
		t.Fatalf("version changed %d -> %d", v1, v2)
	}
}

// TestMigrateConcurrent must reproduce a deadlock regardless of the host's
// CPU count: pgxpool.Config.MaxConns otherwise defaults to
// max(4, runtime.NumCPU()), so on a wide-enough machine the default pool
// dwarfs the handful of connections goose and river's migrator want and the
// old bug (each concurrent Migrate call holding a connection on the advisory
// lock while asking the pool for a second one for the migration itself)
// never starves the pool enough to hang. Pinning MaxConns to 2 and running
// more callers than that guarantees the contention every time.
func TestMigrateConcurrent(t *testing.T) {
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dbtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	const callers = 8
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- db.Migrate(ctx, pool)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migrate: %v", err)
		}
	}
	if v, err := db.Version(ctx, pool); err != nil || v < 1 {
		t.Fatalf("version %d err %v", v, err)
	}
}

func TestOrgQueries(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	o, err := q.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: "home", Name: "Home"})
	if err != nil {
		t.Fatal(err)
	}
	list, err := q.ListOrgs(ctx)
	if err != nil || len(list) != 1 || list[0].ID != o.ID {
		t.Fatalf("list %v err %v", list, err)
	}
	if _, err := q.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: "home", Name: "Dup"}); err == nil {
		t.Fatal("duplicate slug accepted")
	}
	if _, err := q.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: "Bad Slug", Name: "x"}); err == nil {
		t.Fatal("invalid slug accepted")
	}
}
