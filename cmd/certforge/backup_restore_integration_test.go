//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
)

// setCLIEnv points the CLI's config.Load at url with a fixed 32-byte static
// KEK, resetting the file/vault variants bootstrap_admin_integration_test.go
// also has to reset (env vars leak between subtests in the same process).
func setCLIEnv(t *testing.T, url string, kek byte) {
	t.Helper()
	t.Setenv("CF_DATABASE_URL", url)
	t.Setenv("CF_KEK", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{kek}, 32)))
	t.Setenv("CF_KEK_FILE", "")
	t.Setenv("CF_KEK_VAULT_ADDR", "")
	t.Setenv("CF_KEK_PREVIOUS", "")
	t.Setenv("CF_KEK_PREVIOUS_FILE", "")
	t.Setenv("CF_KEK_PREVIOUS_VAULT_ADDR", "")
}

// seedBackupPrereqs migrates url and seeds what runBackup needs before it
// will run at all: the root secret, the KEK canary (both EnsureRoot and
// EnsureCanary — the same calls serve and bootstrap-admin make at boot) and,
// when escrowConfirmed, the backup section's kekEscrowConfirmed. It also
// records one audit event, so TestCLIBackupRestoreRoundTrip's target chain
// has more than just restore.completed to verify.
func seedBackupPrereqs(t *testing.T, ctx context.Context, url string, kek byte, escrowConfirmed bool) []byte { //nolint:revive // ctx-after-t matches internal/backup's own test helpers
	t.Helper()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(bytes.Repeat([]byte{kek}, 32)), bytes.Repeat([]byte{kek}, 32)))
	store := settings.NewStore(sqlcgen.New(pool), env)
	root, err := store.EnsureRoot(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureCanary(ctx); err != nil {
		t.Fatal(err)
	}
	if escrowConfirmed {
		sections := settings.DefaultRegistry()
		sec, ok := sections.Section("backup")
		if !ok {
			t.Fatal("backup section not registered")
		}
		if err := store.PutSection(ctx, sec, json.RawMessage(`{"kekEscrowConfirmed":true}`)); err != nil {
			t.Fatal(err)
		}
	}
	auditKey := crypto.DeriveKey(root, "certforge-audit")
	if err := audit.New(pool, auditKey).Record(ctx, audit.Event{
		Action: "test.seed", ResourceType: "org", ActorType: "system",
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestBackupRefusesWithoutEscrow covers the escrow gate: a database whose
// backup section was never saved (kekEscrowConfirmed defaults to false)
// refuses to write an archive, and --out - must have written nothing to
// stdout before failing.
func TestBackupRefusesWithoutEscrow(t *testing.T) {
	ctx := context.Background()
	url := dbtest.URL(t)
	setCLIEnv(t, url, 1)
	seedBackupPrereqs(t, ctx, url, 1, false)

	var out, errOut bytes.Buffer
	if code := run(ctx, []string{"backup", "--out", "-"}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d, stderr = %q", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "KEK escrow not confirmed") {
		t.Fatalf("errOut = %q", errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %d bytes, want 0 (nothing written before the escrow refusal)", out.Len())
	}
}

// TestCLIBackupRestoreRoundTrip runs certforge backup --out - on a seeded
// source database, pipes the resulting archive as stdin into
// certforge restore --in - --yes against a second, fresh database, and
// checks the target ends up with the same crypto.root and an audit chain
// that verifies end to end with restore.completed as its last row.
func TestCLIBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()

	srcURL := dbtest.URL(t)
	setCLIEnv(t, srcURL, 7)
	srcRoot := seedBackupPrereqs(t, ctx, srcURL, 7, true)

	var archive, backupErr bytes.Buffer
	if code := run(ctx, []string{"backup", "--out", "-"}, &archive, &backupErr); code != 0 {
		t.Fatalf("backup code = %d, stderr = %q", code, backupErr.String())
	}
	if archive.Len() == 0 {
		t.Fatal("backup wrote no bytes to stdout")
	}

	dstURL := dbtest.URL(t)
	setCLIEnv(t, dstURL, 7) // same KEK: restore must unseal what backup sealed

	stdin = bytes.NewReader(archive.Bytes())
	defer func() { stdin = nil }()

	var restoreOut, restoreErr bytes.Buffer
	if code := run(ctx, []string{"restore", "--in", "-", "--yes"}, &restoreOut, &restoreErr); code != 0 {
		t.Fatalf("restore code = %d, stderr = %q", code, restoreErr.String())
	}
	if !strings.Contains(restoreOut.String(), "restore complete") {
		t.Fatalf("restoreOut = %q", restoreOut.String())
	}

	dstPool, err := db.Open(ctx, dstURL)
	if err != nil {
		t.Fatal(err)
	}
	defer dstPool.Close()

	var dstRootSealed []byte
	if err := dstPool.QueryRow(ctx, `SELECT secret FROM settings WHERE key = $1`, settings.RootKey).Scan(&dstRootSealed); err != nil {
		t.Fatal(err)
	}
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(bytes.Repeat([]byte{7}, 32)), bytes.Repeat([]byte{7}, 32)))
	var blob crypto.Blob
	if err := blob.Unmarshal(dstRootSealed); err != nil {
		t.Fatal(err)
	}
	dstRoot, err := env.Decrypt(ctx, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(srcRoot, dstRoot) {
		t.Fatal("restored crypto.root differs from the source database's")
	}

	auditKey := crypto.DeriveKey(dstRoot, "certforge-audit")
	aud := audit.New(dstPool, auditKey)
	if n, err := aud.Verify(ctx); err != nil {
		t.Fatalf("audit chain does not verify after restore: %v (checked %d rows)", err, n)
	}

	var lastAction string
	if err := dstPool.QueryRow(ctx, `SELECT action FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&lastAction); err != nil {
		t.Fatal(err)
	}
	if lastAction != "restore.completed" {
		t.Fatalf("last audit action = %q, want restore.completed", lastAction)
	}
}
