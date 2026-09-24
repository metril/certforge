//go:build integration

package db_test

import (
	"context"
	"sync"
	"testing"

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

func TestMigrateConcurrent(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Empty(t)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
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
