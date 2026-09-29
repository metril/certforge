package backup

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ServeLockKey is the session-level advisory lock every running serve
// process holds shared and every restore takes exclusively (Deviations
// R6). It continues the key numbering audit (0x43460002) and agentca
// (0x43460003) already use.
const ServeLockKey int64 = 0x43460004

// ErrServerRunning means an exclusive lock attempt (restore) found the
// lock already held, shared or exclusive: a serve process is running
// against this database, or another restore already is.
var ErrServerRunning = errors.New("backup: a certforge server is running against this database; stop it first")

// AcquireServeLock takes ServeLockKey shared, on a dedicated pooled
// connection that is held (never returned to the pool) for as long as the
// caller keeps running, and returns a release func that unlocks and
// releases the connection. Any number of serve processes can hold the
// shared lock at once; a restore's exclusive attempt (AcquireRestoreLock)
// blocks on all of them at once. The caller must call release exactly
// once, typically via defer, before exiting.
//
// serve.go calls this before db.Migrate (contract detail): the lock must
// be held before anything else touches the database, so a restore that
// starts between the two can never race a migration.
func AcquireServeLock(ctx context.Context, pool *pgxpool.Pool) (release func(), err error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("backup: acquire lock connection: %w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock_shared($1)", ServeLockKey).Scan(&ok); err != nil {
		conn.Release()
		return nil, fmt.Errorf("backup: serve lock: %w", err)
	}
	if !ok {
		conn.Release()
		return nil, errors.New("a restore holds the database lock")
	}
	return func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock_shared($1)", ServeLockKey)
		conn.Release()
	}, nil
}

// AcquireRestoreLock takes ServeLockKey exclusively, on a dedicated pooled
// connection held for the caller's lifetime, failing immediately
// (ErrServerRunning) rather than blocking if any serve process (shared) or
// another restore (exclusive) already holds it. The caller must call
// release exactly once, typically via defer.
func AcquireRestoreLock(ctx context.Context, pool *pgxpool.Pool) (release func(), err error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("backup: acquire lock connection: %w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", ServeLockKey).Scan(&ok); err != nil {
		conn.Release()
		return nil, fmt.Errorf("backup: restore lock: %w", err)
	}
	if !ok {
		conn.Release()
		return nil, ErrServerRunning
	}
	return func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", ServeLockKey)
		conn.Release()
	}, nil
}
