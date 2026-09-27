//go:build integration

package db_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/metril/certforge/internal/db/dbtest"
)

// pgCheckViolation is the Postgres SQLSTATE for a CHECK constraint failure.
const pgCheckViolation = "23514"

// pgErr extracts *pgconn.PgError from err, or nil when err isn't one.
func pgErr(err error) *pgconn.PgError {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

// TestMigration00011Constraints covers Phase 4A Task 1's migration:
// certificates_unmanaged_no_renewal rejects an unmanaged certificate with a
// next_renew_at, and rate_ledger's kind check rejects an unknown kind.
func TestMigration00011Constraints(t *testing.T) {
	pool, _ := dbtest.New(t)
	ctx := context.Background()
	org := dbtest.Org(t, pool)

	var caID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO cas (org_id, name, preset, directory_url) VALUES ($1, 'LE', 'letsencrypt', 'https://acme-v02.api.letsencrypt.org/directory') RETURNING id`,
		org).Scan(&caID); err != nil {
		t.Fatal(err)
	}

	// managed=true with a next_renew_at (the ordinary case) is fine.
	if _, err := pool.Exec(ctx,
		`INSERT INTO certificates (org_id, name, common_name, managed, next_renew_at) VALUES ($1, 'managed', 'a.example.test', true, now())`,
		org); err != nil {
		t.Fatalf("managed certificate with next_renew_at: %v", err)
	}

	// managed=false with a next_renew_at violates certificates_unmanaged_no_renewal.
	_, err := pool.Exec(ctx,
		`INSERT INTO certificates (org_id, name, common_name, managed, next_renew_at) VALUES ($1, 'unmanaged', 'b.example.test', false, now())`,
		org)
	pe := pgErr(err)
	if pe == nil || pe.Code != pgCheckViolation || pe.ConstraintName != "certificates_unmanaged_no_renewal" {
		t.Fatalf("unmanaged certificate with next_renew_at: err = %v, want CHECK violation on certificates_unmanaged_no_renewal", err)
	}

	// managed=false with no next_renew_at is fine.
	if _, err := pool.Exec(ctx,
		`INSERT INTO certificates (org_id, name, common_name, managed) VALUES ($1, 'unmanaged2', 'c.example.test', false)`,
		org); err != nil {
		t.Fatalf("unmanaged certificate without next_renew_at: %v", err)
	}

	// rate_ledger's kind CHECK.
	if _, err := pool.Exec(ctx, `INSERT INTO rate_ledger (ca_id, kind) VALUES ($1, 'new_order')`, caID); err != nil {
		t.Fatalf("valid rate_ledger kind: %v", err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO rate_ledger (ca_id, kind) VALUES ($1, 'bogus')`, caID)
	if pe := pgErr(err); pe == nil || pe.Code != pgCheckViolation {
		t.Fatalf("unknown rate_ledger kind: err = %v, want CHECK violation (SQLSTATE %s)", err, pgCheckViolation)
	}
}

// TestMigration00011DownUp proves goose down to 00010 and back up to 00011
// succeeds, including with a keyless certificate_versions row present:
// 00011's Down re-imposes private_key NOT NULL, which would otherwise fail
// against exactly that row (review fix round 1) — this seeds one before
// downgrading so the fix is actually exercised, not just syntax-checked
// against an empty table.
func TestMigration00011DownUp(t *testing.T) {
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

	var orgID, certID string
	if err := pool.QueryRow(ctx, `INSERT INTO orgs (slug, name) VALUES ('t', 'T') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, 'c', 'a.example.test') RETURNING id`, orgID,
	).Scan(&certID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO certificate_versions (cert_id, serial, not_before, not_after, sha256_fp, key_type, leaf_der, source)
		 VALUES ($1, '0a', now(), now(), 'fp', 'ec256', 'leaf', 'imported')`, certID); err != nil {
		t.Fatal(err)
	}

	if _, err := p.DownTo(ctx, 10); err != nil {
		t.Fatalf("down to 00010 with a keyless version present: %v", err)
	}
	if _, err := p.UpTo(ctx, 11); err != nil {
		t.Fatalf("up to 00011: %v", err)
	}
}
