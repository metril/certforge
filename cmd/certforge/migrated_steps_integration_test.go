//go:build integration

package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/db/dbtest"
)

func TestAuditMigratedStepRemovals(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	org := dbtest.Org(t, pool)
	var cert, spec, grant, action string
	for q, dst := range map[string]*string{
		`INSERT INTO certificates (org_id, name, common_name) VALUES ('` + org.String() + `', 'c', 'c.example.com') RETURNING id::text`:                           &cert,
		`INSERT INTO output_specs (org_id, name, files) VALUES ('` + org.String() + `', 'l', '[]') RETURNING id::text`:                                            &spec,
		`INSERT INTO actions (org_id, name, kind, phase, config) VALUES ('` + org.String() + `', 'a', 'wait', 'post_deploy', '{"seconds":1}') RETURNING id::text`: &action,
	} {
		if err := pool.QueryRow(ctx, q).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	var target string
	if err := pool.QueryRow(ctx, `INSERT INTO deploy_targets (org_id, name, type, runs_on, config) VALUES ($1, 't', 'ssh', 'server', '{}') RETURNING id::text`, org).Scan(&target); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO client_cert_grants (cert_id, deploy_target_id, output_spec_id) VALUES ($1, $2, $3) RETURNING id::text`, cert, target, spec).Scan(&grant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO migrated_step_removals (grant_id, action_id, old_target_id, reason) VALUES ($1, $2, gen_random_uuid(), 'target_mismatch')`, grant, action); err != nil {
		t.Fatal(err)
	}
	aud := audit.New(pool, []byte("0123456789abcdef0123456789abcdef"))
	if err := auditMigratedStepRemovals(ctx, pool, aud, slog.Default()); err != nil {
		t.Fatal(err)
	}
	var events, left int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'action.step_removed' AND resource_id = $1 AND org_id = $2`, grant, org).Scan(&events)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM migrated_step_removals`).Scan(&left)
	if events != 1 || left != 0 {
		t.Fatalf("events = %d, rows left = %d", events, left)
	}
}
