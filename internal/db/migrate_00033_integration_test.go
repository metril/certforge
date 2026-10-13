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

// TestMigration00033Actions seeds the 00032 schema with hooks, legacy post
// actions and pfSense restart options, then checks the migration keeps hook
// ids, orders steps (hooks, post action, restart), strips the option, and
// that down rebuilds the old columns.
func TestMigration00033Actions(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 32); err != nil {
		t.Fatalf("down to 00032: %v", err)
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
	h1 := str(`INSERT INTO hooks (org_id, name, phase, argv) VALUES ($1, 'h1', 'pre_deploy', '{/bin/a,b}') RETURNING id::text`, org)
	h2 := str(`INSERT INTO hooks (org_id, name, phase, kind, target) VALUES ($1, 'h2', 'post_deploy', 'restart', 'docker:web') RETURNING id::text`, org)
	ssh := str(`INSERT INTO deploy_targets (org_id, name, type, runs_on, config) VALUES ($1, 'edge', 'ssh', 'server', '{}') RETURNING id::text`, org)
	pf := str(`INSERT INTO deploy_targets (org_id, name, type, runs_on, config) VALUES ($1, 'fw', 'pfsense', 'server', '{}') RETURNING id::text`, org)
	cert := str(`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, 'c1', 'c1.example.com') RETURNING id::text`, org)
	client := str(`INSERT INTO clients (org_id, name) VALUES ($1, 'cl') RETURNING id::text`, org)
	cert2 := str(`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, 'c2', 'c2.example.com') RETURNING id::text`, org)
	cert3 := str(`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, 'c3', 'c3.example.com') RETURNING id::text`, org)
	cert4 := str(`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, 'c4', 'c4.example.com') RETURNING id::text`, org)
	spec := str(`INSERT INTO output_specs (org_id, name, files) VALUES ($1, 'l', '[]') RETURNING id::text`, org)
	// Client grant with two hooks in order h2, h1.
	cg := str(`INSERT INTO client_cert_grants (client_id, cert_id, output_spec_id, hook_ids) VALUES ($1, $2, $3, ARRAY[$4::uuid, $5::uuid]) RETURNING id::text`, client, cert, spec, h2, h1)
	// Server grants: modern ssh post action, legacy sshTargetId form, pfSense shell + restart selected, restart none.
	sg1 := str(`INSERT INTO client_cert_grants (cert_id, deploy_target_id, output_spec_id, post_action) VALUES ($1, $2, $3, jsonb_build_object('kind','ssh','targetId',$4::text,'command','reload','timeoutSeconds',30)) RETURNING id::text`, cert, ssh, spec, ssh)
	sg2 := str(`INSERT INTO client_cert_grants (cert_id, deploy_target_id, output_spec_id, post_action) VALUES ($1, $2, $3, jsonb_build_object('sshTargetId',$4::text,'command','legacy')) RETURNING id::text`, cert2, ssh, spec, ssh)
	sg3 := str(`INSERT INTO client_cert_grants (cert_id, deploy_target_id, output_spec_id, post_action, target_options) VALUES ($1, $2, $3, jsonb_build_object('kind','pfsense','targetId',$4::text,'command','ls'), '{"pfsenseRestart":{"mode":"selected","services":["webgui","ipsec"]}}'::jsonb) RETURNING id::text`, cert3, pf, spec, pf)
	sg4 := str(`INSERT INTO client_cert_grants (cert_id, deploy_target_id, output_spec_id, target_options) VALUES ($1, $2, $3, '{"pfsenseRestart":{"mode":"none"}}'::jsonb) RETURNING id::text`, cert4, pf, spec)
	run := str(`INSERT INTO hook_runs (client_id, grant_id, hook_id, phase, exit_code) VALUES ($1, $2, $3, 'pre_deploy', 0) RETURNING id::text`, client, cg, h1)

	if _, err := p.UpTo(ctx, 33); err != nil {
		t.Fatalf("up to 00033: %v", err)
	}

	// Hook ids and config survive; hook_runs still points at the action.
	if got := str(`SELECT config::text FROM actions WHERE id = $1`, h1); !strings.Contains(got, `"argv"`) || !strings.Contains(got, "/bin/a") {
		t.Fatalf("exec config: %s", got)
	}
	if got := str(`SELECT config->>'target' FROM actions WHERE id = $1`, h2); got != "docker:web" {
		t.Fatalf("restart config: %s", got)
	}
	if got := str(`SELECT hook_id::text FROM hook_runs WHERE id = $1`, run); got != h1 {
		t.Fatalf("hook_runs.hook_id = %s, want %s", got, h1)
	}
	// Step order: hooks in hook_ids order.
	if got := str(`SELECT (steps->0->>'action') || ',' || (steps->1->>'action') FROM client_cert_grants WHERE id = $1`, cg); got != h2+","+h1 {
		t.Fatalf("client steps: %s", got)
	}
	// Post actions: kind, name, config, timeout.
	action := func(grant string, idx int, col string) string {
		return str(`SELECT a.`+col+` FROM client_cert_grants g JOIN actions a ON a.id = (g.steps->$2::int->>'action')::uuid WHERE g.id = $1`, grant, idx)
	}
	if k, n, c, to := action(sg1, 0, "kind"), action(sg1, 0, "name"), action(sg1, 0, "config->>'command'"), action(sg1, 0, "timeout_seconds::text"); k != "ssh" || n != "edge post action" || c != "reload" || to != "30" {
		t.Fatalf("sg1: %s %s %s %s", k, n, c, to)
	}
	if k, c, tid, n := action(sg2, 0, "kind"), action(sg2, 0, "config->>'command'"), action(sg2, 0, "config->>'targetId'"), action(sg2, 0, "name"); k != "ssh" || c != "legacy" || tid != ssh || !strings.HasPrefix(n, "edge post action-") {
		t.Fatalf("sg2 (legacy form, name collision): %s %s %s %s", k, c, tid, n)
	}
	// pfSense: shell step then restart step; the option is stripped.
	if k0, k1 := action(sg3, 0, "kind"), action(sg3, 1, "kind"); k0 != "pfsense_shell" || k1 != "pfsense_restart" {
		t.Fatalf("sg3 kinds: %s %s", k0, k1)
	}
	if got := action(sg3, 1, "config->>'mode'"); got != "selected" {
		t.Fatalf("sg3 mode: %s", got)
	}
	if got := action(sg3, 1, "config->'services'->>1"); got != "ipsec" {
		t.Fatalf("sg3 services: %s", got)
	}
	if got := action(sg3, 1, "config->>'targetId'"); got != pf {
		t.Fatalf("sg3 targetId: %s", got)
	}
	if got := action(sg4, 0, "config->>'mode'"); got != "none" {
		t.Fatalf("sg4 mode: %s", got)
	}
	if got := str(`SELECT count(*)::text FROM client_cert_grants WHERE target_options ? 'pfsenseRestart'`); got != "0" {
		t.Fatalf("pfsenseRestart not stripped: %s", got)
	}
	if got := str(`SELECT count(*)::text FROM information_schema.columns WHERE table_name = 'client_cert_grants' AND column_name IN ('hook_ids', 'post_action')`); got != "0" {
		t.Fatalf("old columns remain: %s", got)
	}
	if got := str(`SELECT count(*)::text FROM actions WHERE org_id = $1`, org); got != "7" {
		t.Fatalf("action count: %s, want 7", got)
	}
	// Groups table is usable and capped at 32 ids.
	if _, err := pool.Exec(ctx, `INSERT INTO action_groups (org_id, name, action_ids) VALUES ($1, 'g', ARRAY[$2::uuid])`, org, h1); err != nil {
		t.Fatalf("group: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO action_groups (org_id, name, action_ids) VALUES ($1, 'big', ARRAY(SELECT gen_random_uuid() FROM generate_series(1, 33)))`, org); err == nil {
		t.Fatal("33-action group accepted")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM action_groups`); err != nil {
		t.Fatal(err)
	}

	// Down rebuilds hook_ids and post_action.
	if _, err := p.DownTo(ctx, 32); err != nil {
		t.Fatalf("down to 00032: %v", err)
	}
	if got := str(`SELECT hook_ids[1]::text || ',' || hook_ids[2]::text FROM client_cert_grants WHERE id = $1`, cg); got != h2+","+h1 {
		t.Fatalf("down hook_ids: %s", got)
	}
	if got := str(`SELECT argv[1] FROM hooks WHERE id = $1`, h1); got != "/bin/a" {
		t.Fatalf("down argv: %s", got)
	}
	if got := str(`SELECT post_action->>'kind' || ':' || (post_action->>'command') FROM client_cert_grants WHERE id = $1`, sg1); got != "ssh:reload" {
		t.Fatalf("down sg1 post_action: %s", got)
	}
	if got := str(`SELECT post_action->>'kind' FROM client_cert_grants WHERE id = $1`, sg3); got != "pfsense" {
		t.Fatalf("down sg3 post_action: %s", got)
	}
	if got := str(`SELECT target_options->'pfsenseRestart'->>'mode' FROM client_cert_grants WHERE id = $1`, sg3); got != "selected" {
		t.Fatalf("down sg3 restart: %s", got)
	}
	if got := str(`SELECT count(*)::text FROM hooks`); got != "2" {
		t.Fatalf("down hooks: %s", got)
	}
	if _, err := p.UpTo(ctx, 33); err != nil {
		t.Fatalf("re-up: %v", err)
	}
}
