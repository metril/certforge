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

// TestMigration00040ActionsGrantTarget seeds 00033/00034-shaped data (device
// actions that carry a targetId) and checks matching steps are kept and
// stripped, mismatched ones removed and recorded, and groups inlined.
func TestMigration00040ActionsGrantTarget(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 39); err != nil {
		t.Fatalf("down to 00039: %v", err)
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
	box := str(`INSERT INTO deploy_targets (org_id, name, type, runs_on, config) VALUES ($1, 'box', 'ssh', 'server', '{}') RETURNING id::text`, org)
	spec := str(`INSERT INTO output_specs (org_id, name, files) VALUES ($1, 'l', '[]') RETURNING id::text`, org)
	act := func(name, kind, cfg string) string {
		return str(`INSERT INTO actions (org_id, name, kind, phase, config) VALUES ($1, $2, $3, 'post_deploy', $4::jsonb) RETURNING id::text`, org, name, kind, cfg)
	}
	restart := act("restart", "pikvm_restart", `{"targetId":"`+kvm+`","service":"kvmd-vnc"}`)
	onKvm := act("ssh-kvm", "ssh", `{"targetId":"`+kvm+`","command":"true"}`)
	onBox := act("ssh-box", "ssh", `{"targetId":"`+box+`","command":"true"}`)
	hook := act("hook", "http", `{"method":"GET","url":"https://x.example/h"}`)
	n := 0
	grant := func(target, steps string) string {
		n++
		cert := str(`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, $2, 'c.example.com') RETURNING id::text`, org, "c"+string(rune('0'+n)))
		return str(`INSERT INTO client_cert_grants (cert_id, deploy_target_id, output_spec_id, steps) VALUES ($1, $2, $3, $4::jsonb) RETURNING id::text`, cert, target, spec, steps)
	}
	mixed := str(`INSERT INTO action_groups (org_id, name, action_ids) VALUES ($1, 'mixed', ARRAY[$2::uuid, $3::uuid, $4::uuid]) RETURNING id::text`, org, restart, onBox, hook)
	clean := str(`INSERT INTO action_groups (org_id, name, action_ids) VALUES ($1, 'clean', ARRAY[$2::uuid, $3::uuid]) RETURNING id::text`, org, restart, onKvm)
	g1 := grant(kvm, `[{"action":"`+restart+`"},{"action":"`+onBox+`"},{"action":"`+hook+`"}]`)
	g2 := grant(kvm, `[{"group":"`+mixed+`"},{"action":"`+onKvm+`"}]`)
	g3 := grant(box, `[{"group":"`+mixed+`"}]`)
	g4 := grant(kvm, `[{"group":"`+clean+`"}]`)
	seeded := str(`SELECT count(*)::text FROM client_cert_grants WHERE steps <> '[]'::jsonb AND id IN ($1, $2, $3, $4)`, g1, g2, g3, g4)
	if seeded != "4" {
		t.Fatalf("seeded = %s", seeded)
	}
	steps := func(g string) string { return str(`SELECT steps::text FROM client_cert_grants WHERE id = $1`, g) }

	check := func() {
		t.Helper()
		if got, want := steps(g1), `[{"action": "`+restart+`"}, {"action": "`+hook+`"}]`; got != want {
			t.Fatalf("g1 steps = %s", got)
		}
		if got, want := steps(g2), `[{"action": "`+restart+`"}, {"action": "`+hook+`"}, {"action": "`+onKvm+`"}]`; got != want {
			t.Fatalf("g2 steps (group inlined) = %s", got)
		}
		if got, want := steps(g3), `[{"action": "`+onBox+`"}, {"action": "`+hook+`"}]`; got != want {
			t.Fatalf("g3 steps (group inlined) = %s", got)
		}
		if got, want := steps(g4), `[{"group": "`+clean+`"}]`; got != want {
			t.Fatalf("g4 steps (untouched group) = %s", got)
		}
		if got := str(`SELECT count(*)::text FROM actions WHERE config ? 'targetId'`); got != "0" {
			t.Fatalf("targetId left on %s actions", got)
		}
		if got := str(`SELECT config->>'service' FROM actions WHERE id = $1`, restart); got != "kvmd-vnc" {
			t.Fatalf("service clobbered: %s", got)
		}
		if got := str(`SELECT count(*)::text FROM migrated_step_removals`); got != "3" {
			t.Fatalf("removals = %s, want 3", got)
		}
		if got := str(`SELECT count(*)::text FROM migrated_step_removals WHERE grant_id = $1 AND action_id = $2 AND old_target_id = $3::uuid AND reason = 'target_mismatch'`, g1, onBox, box); got != "1" {
			t.Fatalf("g1 removal: %s", got)
		}
		if got := str(`SELECT count(*)::text FROM migrated_step_removals WHERE grant_id = $1 AND action_id = $2 AND old_target_id = $3::uuid`, g3, restart, kvm); got != "1" {
			t.Fatalf("g3 removal: %s", got)
		}
	}
	if _, err := p.UpTo(ctx, 40); err != nil {
		t.Fatalf("up: %v", err)
	}
	check()
	// Down is a no-op; running up again changes nothing (no duplicate records).
	if _, err := p.DownTo(ctx, 39); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err := p.UpTo(ctx, 40); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	check()
}
