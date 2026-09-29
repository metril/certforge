//go:build integration

package backup_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/backup"
	"github.com/metril/certforge/internal/db/dbtest"
)

// TestServeLockShared covers two concurrent serve processes: both hold the
// shared advisory lock at once, neither blocks the other.
func TestServeLockShared(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Empty(t)

	release1, err := backup.AcquireServeLock(ctx, pool)
	if err != nil {
		t.Fatalf("first serve lock: %v", err)
	}
	defer release1()

	release2, err := backup.AcquireServeLock(ctx, pool)
	if err != nil {
		t.Fatalf("second serve lock: %v", err)
	}
	defer release2()
}

// TestRestoreRefusesLiveServer covers a serve process already holding the
// shared lock: a restore's exclusive attempt must fail immediately with
// ErrServerRunning rather than blocking, and nothing about the database is
// touched by the failed attempt itself.
func TestRestoreRefusesLiveServer(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Empty(t)

	releaseServe, err := backup.AcquireServeLock(ctx, pool)
	if err != nil {
		t.Fatalf("serve lock: %v", err)
	}
	defer releaseServe()

	release, err := backup.AcquireRestoreLock(ctx, pool)
	if err == nil {
		release()
		t.Fatal("AcquireRestoreLock succeeded while a serve lock was held")
	}
	if !errors.Is(err, backup.ErrServerRunning) {
		t.Fatalf("err = %v, want ErrServerRunning", err)
	}
}

// TestServeRefusesDuringRestore covers the reverse: a restore holding the
// lock exclusively blocks a server from starting, with a clear message.
func TestServeRefusesDuringRestore(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Empty(t)

	releaseRestore, err := backup.AcquireRestoreLock(ctx, pool)
	if err != nil {
		t.Fatalf("restore lock: %v", err)
	}
	defer releaseRestore()

	release, err := backup.AcquireServeLock(ctx, pool)
	if err == nil {
		release()
		t.Fatal("AcquireServeLock succeeded while a restore lock was held")
	}
	if !strings.Contains(err.Error(), "restore holds the database lock") {
		t.Fatalf("err = %v, want a message naming the restore lock", err)
	}
}
