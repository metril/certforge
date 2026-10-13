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

// TestMigration00034ExplicitRestarts seeds a pikvm target (one grant already
// restarting) and two pfSense targets (restartServices true and false), then
// checks the created actions and steps, the stripped option, and down.
func TestMigration00034ExplicitRestarts(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 33); err != nil {
		t.Fatalf("down to 00033: %v", err)
	}
	org := dbtest.Org(t, pool)
	str := func(q string, args ...any) string {
		t.Helper()
		var s string
		if err := pool.QueryRow(ctx, q, args...).Scan(&s); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return s
	}
	kvm := str(`INSERT INTO deploy_targets (org_id, name, type, runs_on, config) VALUES ($1, 'kvm', 'pikvm', 'server', '{}') RETURNING id::text`, org)
	pfOn := str(`INSERT INTO deploy_targets (org_id, name, type, runs_on, config) VALUES ($1, 'fw-on', 'pfsense', 'server', '{"restartServices": true, "url": "x"}') RETURNING id::text`, org)
	pfOff := str(`INSERT INTO deploy_targets (org_id, name, type, runs_on, config) VALUES ($1, 'fw-off', 'pfsense', 'server', '{"restartServices": false}') RETURNING id::text`, org)
	spec := str(`INSERT INTO output_specs (org_id, name, files) VALUES ($1, 'l', '[]') RETURNING id::text`, org)
	n := 0
	grant := func(target, steps string) string {
		n++
		cert := str(`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, $2, 'c.example.com') RETURNING id::text`, org, "c"+string(rune('0'+n)))
		return str(`INSERT INTO client_cert_grants (cert_id, deploy_target_id, output_spec_id, steps) VALUES ($1, $2, $3, $4::jsonb) RETURNING id::text`, cert, target, spec, steps)
	}
	// A grant that already restarts: the kind check predates pikvm_restart,
	// so lift it for the seed; the migration re-creates it.
	if _, err := pool.Exec(ctx, `ALTER TABLE actions DROP CONSTRAINT actions_kind_check`); err != nil {
		t.Fatal(err)
	}
	pre := str(`INSERT INTO actions (org_id, name, kind, phase, config) VALUES ($1, 'my restart', 'pikvm_restart', 'post_deploy', jsonb_build_object('targetId', $2::text)) RETURNING id::text`, org, kvm)
	g2 := grant(kvm, `[{"action": "`+pre+`"}]`)
	g1 := grant(kvm, `[]`)
	g3 := grant(pfOn, `[]`)
	g4 := grant(pfOff, `[]`)
	if _, err := p.UpTo(ctx, 34); err != nil {
		t.Fatalf("up: %v", err)
	}
	if got := str(`SELECT count(*)::text FROM actions WHERE org_id = $1 AND kind = 'pikvm_restart' AND name = 'Restart kvmd-nginx · kvm' AND config = jsonb_build_object('targetId', $2::text, 'service', 'kvmd-nginx') AND phase = 'post_deploy'`, org, kvm); got != "1" {
		t.Fatalf("pikvm action: %s", got)
	}
	if got := str(`SELECT count(*)::text FROM actions WHERE org_id = $1 AND kind = 'pfsense_restart' AND name = 'Restart pfSense services · fw-on' AND config = jsonb_build_object('targetId', $2::text, 'mode', 'all')`, org, pfOn); got != "1" {
		t.Fatalf("pfsense action: %s", got)
	}
	if got := str(`SELECT count(*)::text FROM actions WHERE org_id = $1`, org); got != "3" {
		t.Fatalf("action count: %s, want 3", got)
	}
	if got := str(`SELECT steps::text FROM client_cert_grants WHERE id = $1`, g2); got != `[{"action": "`+pre+`"}]` {
		t.Fatalf("g2 steps changed: %s", got)
	}
	if got := str(`SELECT jsonb_array_length(steps)::text FROM client_cert_grants WHERE id = $1`, g1); got != "1" {
		t.Fatalf("g1 steps: %s", got)
	}
	if got := str(`SELECT jsonb_array_length(steps)::text FROM client_cert_grants WHERE id = $1`, g3); got != "1" {
		t.Fatalf("g3 steps: %s", got)
	}
	if got := str(`SELECT steps::text FROM client_cert_grants WHERE id = $1`, g4); got != "[]" {
		t.Fatalf("g4 steps: %s", got)
	}
	if got := str(`SELECT count(*)::text FROM deploy_targets WHERE config ? 'restartServices'`); got != "0" {
		t.Fatalf("restartServices left: %s", got)
	}
	if got := str(`SELECT config->>'url' FROM deploy_targets WHERE id = $1`, pfOn); got != "x" {
		t.Fatalf("config clobbered: %s", got)
	}
	if _, err := p.DownTo(ctx, 33); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := str(`SELECT count(*)::text FROM actions WHERE org_id = $1`, org); got != "0" {
		t.Fatalf("down actions: %s", got)
	}
	if got := str(`SELECT steps::text FROM client_cert_grants WHERE id = $1`, g2); got != "[]" {
		t.Fatalf("down g2 steps: %s", got)
	}
	if got := str(`SELECT steps::text FROM client_cert_grants WHERE id = $1`, g1); got != "[]" {
		t.Fatalf("down g1 steps: %s", got)
	}
	if got := str(`SELECT count(*)::text FROM deploy_targets WHERE type = 'pfsense' AND config->>'restartServices' = 'true'`); got != "2" {
		t.Fatalf("down restartServices: %s", got)
	}
}
