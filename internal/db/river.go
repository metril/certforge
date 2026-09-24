package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

// riverLockKey serializes river migrations across processes; river's
// migrator takes no lock of its own.
const riverLockKey int64 = 0x63667269766572 // "cfriver"

// riverMigratePoolSize is how many connections migrateRiver's own private
// pool opens: one to hold the session-scoped advisory lock for the whole
// run, one more for river's migrator to run each migration version's own
// transaction (see the comment below on why that must stay a real,
// separately-committed transaction per version, not one transaction shared
// across the whole run).
const riverMigratePoolSize = 2

// migrateRiver applies river's job-queue schema (plan 1B, ADR 0003).
//
// It runs against a small pool of its own, opened and closed just for this
// call, instead of the pool the caller shares with the rest of the
// application. Two things rule out reusing the caller's pool directly:
//
//  1. rivermigrate.Migrator.Migrate commits every migration version in its
//     own transaction on purpose (river's own comment on the method: "we wrap
//     each individual migration in its own transaction. Without this,
//     certain migrations ... cannot succeed") — for example version 004
//     adds a Postgres enum value that version 006 then uses in a function
//     body, which Postgres forbids within a single transaction (SQLSTATE
//     55P04, "unsafe use of new value"). So MigrateTx (running the whole
//     batch inside one caller-supplied transaction) is not an option here —
//     confirmed by reproduction: it fails that same way on a fresh database
//     even with a single, non-concurrent caller — and is in fact deprecated
//     upstream for exactly this reason. The migrator needs to freely acquire
//     more than one connection over the course of a run, not just the one
//     holding the advisory lock.
//  2. Holding a connection for the advisory lock and letting the migrator
//     pull further connections from the very same pool that other
//     migrateRiver callers are also blocked on (each holding a connection of
//     its own while it waits for the lock) can exhaust a small shared pool:
//     the lock holder ends up unable to get the second connection it needs,
//     while every connection the other waiters hold is stuck blocked on the
//     lock. Nobody can make progress — a deadlock reproducible with
//     `go test -run TestMigrateConcurrent` under a small enough pool.
//
// A private pool sized for river's own needs (never more than
// riverMigratePoolSize connections at a time: one held for the lock, one
// transient one per migration version) can't be starved by, or starve,
// anything else sharing the caller's pool, and still lets each migration
// version commit on its own as river's migrator requires.
func migrateRiver(ctx context.Context, pool *pgxpool.Pool) error {
	cfg := pool.Config() // (*pgxpool.Pool).Config already returns a defensive copy
	cfg.MaxConns = riverMigratePoolSize
	cfg.MinConns = 0
	riverPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("db: river migrate: open pool: %w", err)
	}
	defer riverPool.Close()

	conn, err := riverPool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("db: river migrate: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", riverLockKey); err != nil {
		return fmt.Errorf("db: river migrate lock: %w", err)
	}
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", riverLockKey) //nolint:errcheck // released with the session anyway

	m, err := rivermigrate.New(riverpgxv5.New(riverPool), nil)
	if err != nil {
		return fmt.Errorf("db: river migrator: %w", err)
	}
	if _, err := m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("db: river migrate: %w", err)
	}
	return nil
}
