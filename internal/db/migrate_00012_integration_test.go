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

// pgUniqueViolation is the Postgres SQLSTATE for a UNIQUE constraint failure.
const pgUniqueViolation = "23505"

// TestMigration00012Constraints covers Phase 5A Task 1's migration: a
// vault-kv deploy target must run on server, a grant needs a client or a
// deploy target, and only one live server grant may exist per (target, cert).
func TestMigration00012Constraints(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	org := dbtest.Org(t, pool)

	var certID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, 'c', 'a.example.test') RETURNING id`,
		org).Scan(&certID); err != nil {
		t.Fatal(err)
	}

	// A vault-kv target must run on server (deploy_targets_type_runs_on_check).
	_, err := pool.Exec(ctx,
		`INSERT INTO deploy_targets (org_id, name, type, runs_on) VALUES ($1, 'kv-agent', 'vault-kv', 'agent')`, org)
	if pe := pgErr(err); pe == nil || pe.Code != pgCheckViolation {
		t.Fatalf("vault-kv target with runs_on=agent: err = %v, want CHECK violation (SQLSTATE %s)", err, pgCheckViolation)
	}

	var targetID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO deploy_targets (org_id, name, type, runs_on) VALUES ($1, 'kv-server', 'vault-kv', 'server') RETURNING id`,
		org).Scan(&targetID); err != nil {
		t.Fatalf("vault-kv target with runs_on=server: %v", err)
	}

	// A grant with neither a client nor a deploy target violates
	// client_cert_grants_client_or_target. output_spec_id is set so the
	// pre-existing client_cert_grants_check (output_spec_id or
	// deploy_target_id) does not also fire and mask which check failed.
	var layoutID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO output_specs (org_id, name) VALUES ($1, 'layout') RETURNING id`, org).Scan(&layoutID); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO client_cert_grants (cert_id, output_spec_id) VALUES ($1, $2)`, certID, layoutID)
	if pe := pgErr(err); pe == nil || pe.Code != pgCheckViolation || pe.ConstraintName != "client_cert_grants_client_or_target" {
		t.Fatalf("grant with no client and no target: err = %v, want CHECK violation on client_cert_grants_client_or_target", err)
	}

	// A server grant (client_id NULL, deploy_target_id set) is fine.
	if _, err := pool.Exec(ctx,
		`INSERT INTO client_cert_grants (cert_id, deploy_target_id) VALUES ($1, $2)`, certID, targetID); err != nil {
		t.Fatalf("first server grant on (target, cert): %v", err)
	}

	// A second live server grant on the same (target, cert) conflicts with
	// client_cert_grants_server_live.
	_, err = pool.Exec(ctx,
		`INSERT INTO client_cert_grants (cert_id, deploy_target_id) VALUES ($1, $2)`, certID, targetID)
	if pe := pgErr(err); pe == nil || pe.Code != pgUniqueViolation || pe.ConstraintName != "client_cert_grants_server_live" {
		t.Fatalf("second live server grant on (target, cert): err = %v, want UNIQUE violation on client_cert_grants_server_live", err)
	}
}

// TestMigration00012DownUp proves goose down to 00011 and back up to 00012
// succeeds, including with a private CA, a server-run deploy target and a
// server grant present: 00012's Down must delete these rows itself before
// its NOT NULL/CHECK constraints could otherwise reject them, and re-running
// Up on the now-clean state must succeed too.
func TestMigration00012DownUp(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Empty(t)
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()

	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up: %v", err)
	}

	var orgID, certID, targetID, grantID string
	if err := pool.QueryRow(ctx, `INSERT INTO orgs (slug, name) VALUES ('t', 'T') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, 'c', 'a.example.test') RETURNING id`, orgID,
	).Scan(&certID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO cas (org_id, name, type, preset, directory_url) VALUES ($1, 'local', 'localca', '', '')`, orgID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO deploy_targets (org_id, name, type, runs_on) VALUES ($1, 'kv', 'vault-kv', 'server') RETURNING id`, orgID,
	).Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO client_cert_grants (cert_id, deploy_target_id) VALUES ($1, $2) RETURNING id`, certID, targetID,
	).Scan(&grantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO server_deployments (grant_id) VALUES ($1)`, grantID); err != nil {
		t.Fatal(err)
	}

	if _, err := p.DownTo(ctx, 11); err != nil {
		t.Fatalf("down to 00011 with a private CA, server target and server grant present: %v", err)
	}
	if _, err := p.UpTo(ctx, 12); err != nil {
		t.Fatalf("up to 00012: %v", err)
	}
}
