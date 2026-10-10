//go:build integration

package backup_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/backup"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/settings"
)

// TestRestoreOlderArchiveWithoutLaterTables: an archive written by a build
// whose Manifest lacked the newest table (enrollment_requests) must still restore; the
// missing table simply stays empty.
func TestRestoreOlderArchiveWithoutLaterTables(t *testing.T) {
	ctx := context.Background()
	srcPool, srcQ := dbtest.New(t)
	seedAllTables(t, ctx, srcPool)
	be := newBackupEnv(srcQ, testKey(7))
	opts := be.writeOpts(ctx, t)

	var root []byte
	if err := srcPool.QueryRow(ctx, `SELECT secret FROM settings WHERE key = $1`, settings.RootKey).Scan(&root); err != nil {
		t.Fatal(err)
	}
	tx, err := srcPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if backup.Manifest[len(backup.Manifest)-1] != "enrollment_requests" {
		t.Fatal("test assumes enrollment_requests is the last Manifest table")
	}
	older := backup.Manifest[:len(backup.Manifest)-1]
	var archive bytes.Buffer
	if _, err := backup.WriteWithTablesForTest(ctx, tx, &archive, opts, root, older); err != nil {
		t.Fatal(err)
	}

	dstPool := dbtest.Empty(t)
	if _, err := backup.Restore(ctx, dstPool, bytes.NewReader(archive.Bytes()), be.restoreOpts()); err != nil {
		t.Fatalf("restore older archive: %v", err)
	}
	counts := tableCounts(t, ctx, dstPool, []string{"enrollment_requests", "orgs"})
	if counts["enrollment_requests"] != 0 {
		t.Errorf("enrollment_requests rows = %d, want 0", counts["enrollment_requests"])
	}
	if counts["orgs"] == 0 {
		t.Error("orgs not restored")
	}
}
