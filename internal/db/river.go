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

// migrateRiver applies river's job-queue schema (plan 1B, ADR 0003).
func migrateRiver(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("db: river migrate: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", riverLockKey); err != nil {
		return fmt.Errorf("db: river migrate lock: %w", err)
	}
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", riverLockKey) //nolint:errcheck // released with the session anyway
	m, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return fmt.Errorf("db: river migrator: %w", err)
	}
	if _, err := m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("db: river migrate: %w", err)
	}
	return nil
}
