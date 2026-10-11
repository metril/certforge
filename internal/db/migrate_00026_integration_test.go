//go:build integration

package db_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/metril/certforge/internal/db/dbtest"
)

// TestMigration00026GrantTargetOptions checks the backfill moves a Traefik
// target's defaultCert onto one live grant per client (the certificate whose
// name sorts first), leaves other targets alone, and that down drops the column.
func TestMigration00026GrantTargetOptions(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 25); err != nil {
		t.Fatalf("down to 00025: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='client_cert_grants' AND column_name='target_options'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("column after down: %d, %v", n, err)
	}

	org := dbtest.Org(t, pool)
	mustID := func(sql string, args ...any) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	mkCert := func(n string) uuid.UUID {
		return mustID(`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, $2, $2) RETURNING id`, org, n)
	}
	cert := mkCert("a")
	target := func(name, typ, cfg string) uuid.UUID {
		return mustID(`INSERT INTO deploy_targets (org_id, name, type, config) VALUES ($1, $2, $3, $4::jsonb) RETURNING id`, org, name, typ, cfg)
	}
	grantC := func(client, c, tgt uuid.UUID, removed bool) uuid.UUID {
		return mustID(`INSERT INTO client_cert_grants (client_id, cert_id, deploy_target_id, removed_at)
			VALUES ($1, $2, $3, CASE WHEN $4 THEN now() END) RETURNING id`, client, c, tgt, removed)
	}
	grant := func(client, tgt uuid.UUID, removed bool) uuid.UUID {
		return grantC(client, cert, tgt, removed)
	}
	cl := func(n string) uuid.UUID {
		return mustID(`INSERT INTO clients (org_id, name) VALUES ($1, $2) RETURNING id`, org, n)
	}
	tr := target("tr", "traefik", `{"dir":"/d","defaultCert":true}`)
	trOff := target("tr-off", "traefik", `{"dir":"/d","defaultCert":false}`)
	vk := target("vk", "vault-kv", `{"path":"x","defaultCert":true}`)
	gLive := grant(cl("c1"), tr, false)
	gGone := grant(cl("c2"), tr, true)
	gOff := grant(cl("c3"), trOff, false)
	gVault := grant(cl("c4"), vk, false)
	multi := cl("c5")
	gZeta := grantC(multi, mkCert("zeta"), tr, false)
	gAlpha := grantC(multi, mkCert("Alpha"), tr, false)
	gMid := grantC(multi, mkCert("mid"), tr, false)
	gOther := grantC(cl("c6"), mkCert("other"), tr, false)

	if _, err := p.UpTo(ctx, 26); err != nil {
		t.Fatalf("up to 00026: %v", err)
	}
	opts := func(id uuid.UUID) string {
		var s string
		if err := pool.QueryRow(ctx, `SELECT target_options::text FROM client_cert_grants WHERE id=$1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	for id, want := range map[uuid.UUID]string{
		gLive: `{"defaultCert": true}`, gGone: `{}`, gOff: `{}`, gVault: `{}`,
		gAlpha: `{"defaultCert": true}`, gZeta: `{}`, gMid: `{}`, gOther: `{"defaultCert": true}`,
	} {
		if got := opts(id); got != want {
			t.Errorf("grant %s target_options = %s, want %s", id, got, want)
		}
	}
	has := func(id uuid.UUID) bool {
		var b bool
		if err := pool.QueryRow(ctx, `SELECT config ? 'defaultCert' FROM deploy_targets WHERE id=$1`, id).Scan(&b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	if has(tr) || has(trOff) {
		t.Error("traefik target config still has defaultCert")
	}
	if !has(vk) {
		t.Error("vault-kv target config lost defaultCert")
	}

	if _, err := p.DownTo(ctx, 25); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='client_cert_grants' AND column_name='target_options'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("column after second down: %d, %v", n, err)
	}
}
