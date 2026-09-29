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

// TestMigration00014DownUp proves goose down to 00013 and back up to 00014
// succeeds, with deployments and server_deployments rows present (final
// review fix wave, finding 1: state_changed_at, ADD COLUMN ... DEFAULT
// now() NOT NULL, and its DROP COLUMN counterpart in the Down script) — a
// non-empty table is what actually exercises the DROP COLUMN direction,
// not just the schema shape on an empty one.
func TestMigration00014DownUp(t *testing.T) {
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

	var orgID, certID, clientID, agentTargetID, serverTargetID, agentGrantID, serverGrantID string
	if err := pool.QueryRow(ctx, `INSERT INTO orgs (slug, name) VALUES ('t14', 'T14') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO certificates (org_id, name, common_name, sans) VALUES ($1, 'c14', 'c14.example.test', '{}') RETURNING id`,
		orgID).Scan(&certID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO clients (org_id, name, status) VALUES ($1, 'client14', 'active') RETURNING id`,
		orgID).Scan(&clientID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO deploy_targets (org_id, name, type, runs_on) VALUES ($1, 'agent14', 'traefik', 'agent') RETURNING id`,
		orgID).Scan(&agentTargetID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO deploy_targets (org_id, name, type, runs_on) VALUES ($1, 'server14', 'vault-kv', 'server') RETURNING id`,
		orgID).Scan(&serverTargetID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO client_cert_grants (client_id, cert_id, deploy_target_id) VALUES ($1, $2, $3) RETURNING id`,
		clientID, certID, agentTargetID).Scan(&agentGrantID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO client_cert_grants (cert_id, deploy_target_id) VALUES ($1, $2) RETURNING id`,
		certID, serverTargetID).Scan(&serverGrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO deployments (grant_id, state_changed_at) VALUES ($1, now())`, agentGrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO server_deployments (grant_id, status, state_changed_at) VALUES ($1, 'pending', now())`, serverGrantID); err != nil {
		t.Fatal(err)
	}

	if _, err := p.DownTo(ctx, 13); err != nil {
		t.Fatalf("down to 00013 with deployments/server_deployments rows present: %v", err)
	}
	if _, err := p.UpTo(ctx, 14); err != nil {
		t.Fatalf("up to 00014: %v", err)
	}
}
