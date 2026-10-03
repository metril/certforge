//go:build integration

package backup_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/backup"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// backupEnv bundles what Write and Restore need from a configured
// envelope, standing in for the Service Task 12 will build from
// settings.Store and internal/crypto.
type backupEnv struct {
	env   *crypto.Envelope
	store *settings.Store
}

func newBackupEnv(q *sqlcgen.Queries, kek []byte) backupEnv {
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(kek), kek))
	return backupEnv{env: env, store: settings.NewStore(q, env)}
}

// writeOpts seeds the root and canary (EnsureRoot/EnsureCanary, the same
// calls serve makes at boot) and returns the WriteOpts Write needs.
func (b backupEnv) writeOpts(ctx context.Context, t *testing.T) backup.WriteOpts {
	t.Helper()
	root, err := b.store.EnsureRoot(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.store.EnsureCanary(ctx); err != nil {
		t.Fatal(err)
	}
	return backup.WriteOpts{
		BaseKey:    crypto.DeriveKey(root, "certforge-backup"),
		KEKID:      b.env.KEKID(),
		AppVersion: "test",
	}
}

// restoreOpts builds RestoreOpts against b's envelope: Unseal decrypts a
// marshalled crypto.Blob, VerifyCanary reads settings.CanaryKey through
// Restore's own transaction (tx), the same shape a real caller (Task
// 11/12) will use.
func (b backupEnv) restoreOpts() backup.RestoreOpts {
	return backup.RestoreOpts{
		Unseal: func(ctx context.Context, sealed []byte) ([]byte, error) {
			var blob crypto.Blob
			if err := blob.Unmarshal(sealed); err != nil {
				return nil, err
			}
			return b.env.Decrypt(ctx, blob)
		},
		VerifyCanary: func(ctx context.Context, tx pgx.Tx) error {
			var raw []byte
			if err := tx.QueryRow(ctx, `SELECT secret FROM settings WHERE key = $1`, settings.CanaryKey).Scan(&raw); err != nil {
				return err
			}
			var blob crypto.Blob
			if err := blob.Unmarshal(raw); err != nil {
				return err
			}
			pt, err := b.env.Decrypt(ctx, blob)
			if err != nil {
				return err
			}
			if !bytes.Equal(pt, crypto.CanaryPlaintext) {
				return settings.ErrCanaryMismatch
			}
			return nil
		},
	}
}

// seedAllTables inserts one minimal, FK-valid row into every table in
// backup.Manifest except goose_db_version and settings (settings is
// already non-empty: writeOpts's EnsureRoot/EnsureCanary seeded it),
// exercising TestWriteRestoreRoundTrip and TestManifestCoversAllTables'
// premise that every application table is actually covered.
func seedAllTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) { //nolint:revive // ctx-after-t matches this file's other helpers
	t.Helper()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	scanID := func(sql string, args ...any) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
		return id
	}

	org := scanID(`INSERT INTO orgs (slug, name) VALUES ('seed', 'Seed') RETURNING id`)
	scanID(`INSERT INTO sites (org_id, name) VALUES ($1, 'site1') RETURNING id`, org)
	user := scanID(`INSERT INTO users (email, display_name) VALUES ('seed@example.test', 'Seed User') RETURNING id`)
	exec(`INSERT INTO sessions (id, user_id, csrf, expires_at) VALUES ('sess1', $1, 'csrf', now() + interval '1 hour')`, user)
	exec(`INSERT INTO role_bindings (subject_type, subject, role, org_id) VALUES ('user', $1, 'admin', $2)`, user.String(), org)
	exec(`INSERT INTO audit_events (ts, actor_type, action, resource_type, prev_hash, hash)
		VALUES (now(), 'system', 'test.seed', 'org', E'\\x01', E'\\x02')`)

	ca := scanID(`INSERT INTO cas (org_id, name, type, preset, directory_url) VALUES ($1, 'ca1', 'acme', 'letsencrypt', 'https://acme.example/directory') RETURNING id`, org)
	scanID(`INSERT INTO acme_accounts (org_id, ca_id, email, account_key, registration_uri) VALUES ($1, $2, 'ops@example.test', E'\\x00', 'https://acme.example/acct/1') RETURNING id`, org, ca)
	scanID(`INSERT INTO dns_provider_credentials (org_id, name, provider_code, secret_cfg) VALUES ($1, 'dns1', 'manual', E'\\x00') RETURNING id`, org)
	exec(`INSERT INTO issuance_defaults (org_id) VALUES ($1)`, org)

	cert := scanID(`INSERT INTO certificates (org_id, name, common_name) VALUES ($1, 'cert1', 'cert1.example.test') RETURNING id`, org)
	version := scanID(`INSERT INTO certificate_versions (cert_id, serial, not_before, not_after, sha256_fp, key_type, leaf_der)
		VALUES ($1, 'serial1', now(), now() + interval '90 days', 'fp1', 'ec256', E'\\x00') RETURNING id`, cert)
	exec(`UPDATE certificates SET current_version_id = $1 WHERE id = $2`, version, cert)
	attempt := scanID(`INSERT INTO issuance_attempts (cert_id) VALUES ($1) RETURNING id`, cert)
	exec(`INSERT INTO manual_dns_pending (attempt_id, cert_id, domain, fqdn, value, ttl, expires_at)
		VALUES ($1, $2, 'example.test', '_acme-challenge.example.test', 'v', 120, now() + interval '1 hour')`, attempt, cert)

	exec(`INSERT INTO api_keys (name, prefix, secret_hash, scopes, org_id, created_by) VALUES ('key1', '0123456789ab', E'\\x00', '{admin}', $1, $2)`, org, user)

	agentCA := scanID(`INSERT INTO agent_cas (cert_der, key, not_before, not_after) VALUES (E'\\x00', E'\\x00', now(), now() + interval '1 year') RETURNING id`)
	client := scanID(`INSERT INTO clients (org_id, name, agent_ca_id) VALUES ($1, 'client1', $2) RETURNING id`, org, agentCA)
	exec(`INSERT INTO enrollment_tokens (client_id, token_hash, expires_at) VALUES ($1, E'\\x00', now() + interval '1 hour')`, client)
	outputSpec := scanID(`INSERT INTO output_specs (org_id, name) VALUES ($1, 'output1') RETURNING id`, org)
	target := scanID(`INSERT INTO deploy_targets (org_id, name, type, runs_on) VALUES ($1, 'target1', 'traefik', 'agent') RETURNING id`, org)
	exec(`INSERT INTO hooks (org_id, name, phase, argv) VALUES ($1, 'hook1', 'pre_deploy', '{/bin/true}')`, org)

	grant := scanID(`INSERT INTO client_cert_grants (client_id, cert_id, output_spec_id) VALUES ($1, $2, $3) RETURNING id`, client, cert, outputSpec)
	exec(`INSERT INTO deployments (grant_id) VALUES ($1)`, grant)
	exec(`INSERT INTO hook_runs (client_id, phase, exit_code) VALUES ($1, 'pre_deploy', 0)`, client)

	exec(`INSERT INTO rate_ledger (ca_id, kind) VALUES ($1, 'new_order')`, ca)

	serverGrant := scanID(`INSERT INTO client_cert_grants (deploy_target_id, cert_id) VALUES ($1, $2) RETURNING id`, target, cert)
	exec(`INSERT INTO server_deployments (grant_id) VALUES ($1)`, serverGrant)

	channel := scanID(`INSERT INTO notification_channels (org_id, name, type) VALUES ($1, 'chan1', 'webhook') RETURNING id`, org)
	event := scanID(`INSERT INTO notification_events (kind, severity, resource_type, summary, dedupe_key)
		VALUES ('test', 'info', 'channel', 'seed event', 'seed-dedupe') RETURNING id`)
	exec(`INSERT INTO notification_deliveries (event_id, channel_id) VALUES ($1, $2)`, event, channel)
	exec(`INSERT INTO external_monitors (org_id, name, host) VALUES ($1, 'mon1', 'a.example.test')`, org)
}

// tableCounts returns the row count of every table in tables.
func tableCounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tables []string) map[string]int64 { //nolint:revive
	t.Helper()
	out := make(map[string]int64, len(tables))
	for _, table := range tables {
		var n int64
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		out[table] = n
	}
	return out
}

// TestWriteRestoreRoundTrip seeds every table, backs the source database
// up, restores the archive into a fresh database, and checks the two
// databases end up identical where it matters: row counts, the
// crypto.root row byte for byte, and that sequence-backed ids keep
// advancing (not colliding with restored ones).
func TestWriteRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	srcPool, srcQ := dbtest.New(t)
	seedAllTables(t, ctx, srcPool)
	be := newBackupEnv(srcQ, testKey(1))
	opts := be.writeOpts(ctx, t)

	var archive bytes.Buffer
	summary, err := backup.Write(ctx, srcPool, &archive, opts)
	if err != nil {
		t.Fatal(err)
	}
	if summary.SizeBytes == 0 || len(summary.Tables) != len(backup.Manifest) {
		t.Fatalf("summary = %+v", summary)
	}

	dstPool := dbtest.Empty(t)
	header, err := backup.Restore(ctx, dstPool, bytes.NewReader(archive.Bytes()), be.restoreOpts())
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if header.MigrationVersion < 13 {
		t.Fatalf("header.MigrationVersion = %d", header.MigrationVersion)
	}

	loadTables := make([]string, 0, len(backup.Manifest)-1)
	for _, table := range backup.Manifest {
		if table != "goose_db_version" {
			loadTables = append(loadTables, table)
		}
	}
	srcCounts := tableCounts(t, ctx, srcPool, loadTables)
	dstCounts := tableCounts(t, ctx, dstPool, loadTables)
	for _, table := range loadTables {
		if srcCounts[table] != dstCounts[table] {
			t.Errorf("table %s: source has %d rows, restored has %d", table, srcCounts[table], dstCounts[table])
		}
		if srcCounts[table] == 0 {
			t.Errorf("table %s: seeded with 0 rows, TestWriteRestoreRoundTrip covers nothing for it", table)
		}
	}

	var srcRoot, dstRoot []byte
	if err := srcPool.QueryRow(ctx, `SELECT secret FROM settings WHERE key = $1`, settings.RootKey).Scan(&srcRoot); err != nil {
		t.Fatal(err)
	}
	if err := dstPool.QueryRow(ctx, `SELECT secret FROM settings WHERE key = $1`, settings.RootKey).Scan(&dstRoot); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(srcRoot, dstRoot) {
		t.Fatal("restored crypto.root differs from source")
	}

	// Sequence continuity: audit_events.id is bigserial; a fresh insert
	// after restore must not collide with the restored row's id.
	var newID int64
	if err := dstPool.QueryRow(ctx, `INSERT INTO audit_events (ts, actor_type, action, resource_type, prev_hash, hash)
		VALUES (now(), 'system', 'post.restore', 'org', E'\\x03', E'\\x04') RETURNING id`).Scan(&newID); err != nil {
		t.Fatalf("insert after restore (sequence not reset?): %v", err)
	}
}

// TestRestoreLoadsAtMaxVersion covers a header genuinely stamped at an
// older migration version (12): Restore must still load at 13, the first
// version with deferrable foreign keys, never lower. The source database
// is migrated to exactly 13 (db.MigrateTo), not the binary's own current
// latest (final review fix wave, finding 1's migration 00014 added a
// column beyond 13 — dumping a database physically ahead of the version
// the header ends up claiming would make restoreLoad's COPY into a
// target only migrated to that claimed version fail on the extra column,
// a mismatch that can never happen for a genuine backup, where the
// header's version and the physical schema always move together): only
// the goose_db_version bookkeeping row for 13 is marked not-applied, so
// Write's own snapshot read legitimately sees 12 while every column
// Manifest expects at 13 still physically exists to dump — the resulting
// header is genuine, not edited after the fact (which would break the
// chunk stream's AAD binding to the header's exact bytes; see the
// format's tamper detection).
// TestWriteSpoolRoundTripLeavesNoTempFiles: tables are spooled to a private
// directory under SpoolDir; the archive still restores, nothing remains in
// SpoolDir afterwards, and a stale spool directory from a crashed run is
// cleaned at the start of a backup.
func TestWriteSpoolRoundTripLeavesNoTempFiles(t *testing.T) {
	ctx := context.Background()
	srcPool, srcQ := dbtest.New(t)
	seedAllTables(t, ctx, srcPool)
	be := newBackupEnv(srcQ, testKey(1))
	opts := be.writeOpts(ctx, t)

	spoolDir := t.TempDir()
	stale := filepath.Join(spoolDir, ".certforge-spool-crashed")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "settings.csv"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	opts.SpoolDir = spoolDir

	var archive bytes.Buffer
	if _, err := backup.Write(ctx, srcPool, &archive, opts); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(spoolDir); err != nil || len(entries) != 0 {
		t.Fatalf("spool dir not empty: %v %v", entries, err)
	}

	dstPool := dbtest.Empty(t)
	if _, err := backup.Restore(ctx, dstPool, bytes.NewReader(archive.Bytes()), be.restoreOpts()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, tbl := range backup.Manifest {
		if tableCounts(t, ctx, srcPool, []string{tbl})[tbl] != tableCounts(t, ctx, dstPool, []string{tbl})[tbl] {
			t.Fatalf("table %s row count differs after restore", tbl)
		}
	}
}

func TestRestoreLoadsAtMaxVersion(t *testing.T) {
	ctx := context.Background()
	srcPool := dbtest.Empty(t)
	if err := db.MigrateTo(ctx, srcPool, 13); err != nil {
		t.Fatal(err)
	}
	srcQ := sqlcgen.New(srcPool)
	seedAllTables(t, ctx, srcPool)
	be := newBackupEnv(srcQ, testKey(2))
	opts := be.writeOpts(ctx, t)

	if _, err := srcPool.Exec(ctx, `UPDATE goose_db_version SET is_applied = false WHERE version_id = 13`); err != nil {
		t.Fatal(err)
	}

	var archive bytes.Buffer
	if _, err := backup.Write(ctx, srcPool, &archive, opts); err != nil {
		t.Fatal(err)
	}

	dstPool := dbtest.Empty(t)
	header, err := backup.Restore(ctx, dstPool, bytes.NewReader(archive.Bytes()), be.restoreOpts())
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if header.MigrationVersion != 12 {
		t.Fatalf("header.MigrationVersion = %d, want 12 (unchanged, only the load target is raised)", header.MigrationVersion)
	}
	if v, err := db.Version(ctx, dstPool); err != nil || v < 13 {
		t.Fatalf("db.Version = %d, err = %v, want >= 13", v, err)
	}
}

// TestRestoreRefusesNewerDatabase covers a target database already
// migrated (by version number, however that happened) past what this
// backup and this binary support.
func TestRestoreRefusesNewerDatabase(t *testing.T) {
	ctx := context.Background()
	srcPool, srcQ := dbtest.New(t)
	seedAllTables(t, ctx, srcPool)
	be := newBackupEnv(srcQ, testKey(3))
	opts := be.writeOpts(ctx, t)

	var archive bytes.Buffer
	if _, err := backup.Write(ctx, srcPool, &archive, opts); err != nil {
		t.Fatal(err)
	}

	dstPool, _ := dbtest.New(t)
	if _, err := dstPool.Exec(ctx, `INSERT INTO goose_db_version (version_id, is_applied) VALUES (999, true)`); err != nil {
		t.Fatal(err)
	}

	if _, err := backup.Restore(ctx, dstPool, bytes.NewReader(archive.Bytes()), be.restoreOpts()); !errors.Is(err, backup.ErrNewerDatabase) {
		t.Fatalf("err = %v, want ErrNewerDatabase", err)
	}
}

// TestRestoreKEKMismatchWritesNothing covers restoring an archive with a
// configured envelope that cannot unseal its RootSealed: Restore must
// fail before touching the database at all.
func TestRestoreKEKMismatchWritesNothing(t *testing.T) {
	ctx := context.Background()
	srcPool, srcQ := dbtest.New(t)
	seedAllTables(t, ctx, srcPool)
	be := newBackupEnv(srcQ, testKey(4))
	opts := be.writeOpts(ctx, t)

	var archive bytes.Buffer
	if _, err := backup.Write(ctx, srcPool, &archive, opts); err != nil {
		t.Fatal(err)
	}

	dstPool := dbtest.Empty(t)
	wrongEnv := newBackupEnv(sqlcgen.New(dstPool), testKey(5)) // a different KEK entirely

	if _, err := backup.Restore(ctx, dstPool, bytes.NewReader(archive.Bytes()), wrongEnv.restoreOpts()); !errors.Is(err, backup.ErrKEKMismatch) {
		t.Fatalf("err = %v, want ErrKEKMismatch", err)
	}

	var n int
	if err := dstPool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("target database has %d tables after a KEK-mismatch restore attempt, want 0 (nothing migrated or written)", n)
	}
}

// TestRestoreRootMismatchRollsBack covers a crafted archive whose settings
// CSV holds a different crypto.root than the header's own RootSealed: the
// KEK check passes (RootSealed itself decodes fine), but the freshly
// loaded row disagrees, and the whole restore must roll back. Write itself
// can no longer produce this archive (batch-4 review, Critical: it now
// always reads crypto.root live from the very snapshot it dumps from, so
// the two can never disagree) — this test instead simulates a
// hand-crafted or buggy archive via backup.WriteWithRootForTest
// (internal/backup/export_test.go), proving restoreLoad's own
// root-consistency check is real defense in depth, independent of
// whatever produced the archive.
func TestRestoreRootMismatchRollsBack(t *testing.T) {
	ctx := context.Background()
	srcPool, srcQ := dbtest.New(t)
	seedAllTables(t, ctx, srcPool)
	be := newBackupEnv(srcQ, testKey(6))
	opts := be.writeOpts(ctx, t)

	// A forged root: same KEK (so it decodes fine), different plaintext,
	// deliberately different from what the source database's own
	// settings.secret row (and therefore the dumped settings.csv) holds.
	forged, err := be.env.Encrypt(ctx, bytes.Repeat([]byte{0xEE}, 32))
	if err != nil {
		t.Fatal(err)
	}

	tx, err := srcPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var archive bytes.Buffer
	if _, err := backup.WriteWithRootForTest(ctx, tx, &archive, opts, forged.Marshal()); err != nil {
		t.Fatal(err)
	}
	// The header now carries the forged root; the dumped settings.csv
	// (read from the same snapshot as every other table) still carries
	// the real one, so the two disagree exactly as the scenario requires.

	dstPool := dbtest.Empty(t)

	if _, err := backup.Restore(ctx, dstPool, bytes.NewReader(archive.Bytes()), be.restoreOpts()); !errors.Is(err, backup.ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}

	// MigrateTo commits its own migrations outside Restore's load
	// transaction (goose commits each version separately; see
	// internal/db/river.go's comment on why), so the schema itself exists
	// even after a rolled-back restore — only the data load rolls back.
	// Every table Restore would have loaded must be empty.
	loadTables := make([]string, 0, len(backup.Manifest)-1)
	for _, table := range backup.Manifest {
		if table != "goose_db_version" {
			loadTables = append(loadTables, table)
		}
	}
	for table, n := range tableCounts(t, ctx, dstPool, loadTables) {
		if n != 0 {
			t.Errorf("table %s has %d rows after a rolled-back restore, want 0", table, n)
		}
	}
}

// TestRestoreIntoPopulatedDatabaseIsAuditConflict: restoring over a database
// that already holds the archive's audit rows (audit_events is never
// truncated) fails on the primary key. That is an operator mistake, not a
// tampered archive, and must say so.
func TestRestoreIntoPopulatedDatabaseIsAuditConflict(t *testing.T) {
	ctx := context.Background()
	srcPool, srcQ := dbtest.New(t)
	seedAllTables(t, ctx, srcPool)
	be := newBackupEnv(srcQ, testKey(8))

	var archive bytes.Buffer
	if _, err := backup.Write(ctx, srcPool, &archive, be.writeOpts(ctx, t)); err != nil {
		t.Fatal(err)
	}

	_, err := backup.Restore(ctx, srcPool, bytes.NewReader(archive.Bytes()), be.restoreOpts())
	if !errors.Is(err, backup.ErrAuditConflict) {
		t.Fatalf("err = %v, want ErrAuditConflict", err)
	}
	if errors.Is(err, backup.ErrTampered) {
		t.Fatalf("err = %v, must not be reported as ErrTampered", err)
	}
}

// TestRestoreCorruptChunkDuringCopyIsTampered: a chunk that fails to
// authenticate while a table's COPY is still reading it must surface as
// ErrTampered (pgconn reports only the server's cancel error for a failed
// COPY source, so the reader's own error has to be recovered separately).
// audit_events is padded so its CSV spans several chunks and the second
// chunk is read mid-COPY.
func TestRestoreCorruptChunkDuringCopyIsTampered(t *testing.T) {
	ctx := context.Background()
	srcPool, srcQ := dbtest.New(t)
	seedAllTables(t, ctx, srcPool)
	if _, err := srcPool.Exec(ctx, `INSERT INTO audit_events (ts, actor_type, action, resource_type, details, prev_hash, hash)
		SELECT now(), 'system', 'test.pad', 'org', jsonb_build_object('pad', repeat(md5(g::text), 4000)), decode(md5(g::text), 'hex'), E'\\x02'
		FROM generate_series(1, 20) g`); err != nil {
		t.Fatal(err)
	}
	be := newBackupEnv(srcQ, testKey(9))

	var archive bytes.Buffer
	if _, err := backup.Write(ctx, srcPool, &archive, be.writeOpts(ctx, t)); err != nil {
		t.Fatal(err)
	}
	data := archive.Bytes()

	// Locate the second chunk: skip the header, then the first chunk's
	// uint32 length prefix and body.
	r := bytes.NewReader(data)
	if _, err := backup.ReadHeader(r); err != nil {
		t.Fatal(err)
	}
	first := len(data) - r.Len()
	second := first + 4 + int(binary.BigEndian.Uint32(data[first:first+4]))
	if second+4+16 >= len(data) {
		t.Fatal("archive has fewer than two chunks")
	}
	data[second+4+8] ^= 0xFF

	dstPool := dbtest.Empty(t)
	if _, err := backup.Restore(ctx, dstPool, bytes.NewReader(data), be.restoreOpts()); !errors.Is(err, backup.ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}
}

// TestRestoreCanaryFailureRollsBack covers a crafted archive whose canary
// row does not decrypt to crypto.CanaryPlaintext under the caller's
// envelope, even though the root itself matches: the whole restore must
// still roll back.
func TestRestoreCanaryFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	srcPool, srcQ := dbtest.New(t)
	seedAllTables(t, ctx, srcPool)
	be := newBackupEnv(srcQ, testKey(7))
	opts := be.writeOpts(ctx, t)

	forgedCanary, err := be.env.Encrypt(ctx, []byte("not the real canary"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srcPool.Exec(ctx, `UPDATE settings SET secret = $1 WHERE key = $2`, forgedCanary.Marshal(), settings.CanaryKey); err != nil {
		t.Fatal(err)
	}

	var archive bytes.Buffer
	if _, err := backup.Write(ctx, srcPool, &archive, opts); err != nil {
		t.Fatal(err)
	}

	dstPool := dbtest.Empty(t)
	if _, err := backup.Restore(ctx, dstPool, bytes.NewReader(archive.Bytes()), be.restoreOpts()); !errors.Is(err, backup.ErrTampered) {
		t.Fatalf("err = %v, want ErrTampered", err)
	}

	var n int
	if err := dstPool.QueryRow(ctx, `SELECT count(*) FROM settings`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("settings has %d rows after a rolled-back restore, want 0", n)
	}
}

// TestWriteHeaderMatchesSnapshot proves the guarantee Write's REPEATABLE
// READ, read-only transaction depends on: once its snapshot begins (its
// first statement), a schema change committed on another connection is
// not visible to it, so the header's own MigrationVersion (and the dumped
// rows) reflect the database as it was at BEGIN, not as it ends up by the
// time the dump finishes.
func TestWriteHeaderMatchesSnapshot(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var before int64
	if err := tx.QueryRow(ctx, `SELECT version_id FROM goose_db_version WHERE is_applied ORDER BY id DESC LIMIT 1`).Scan(&before); err != nil {
		t.Fatal(err)
	}

	// A separate connection commits a schema-version change after the
	// snapshot above has already begun.
	if _, err := pool.Exec(ctx, `INSERT INTO goose_db_version (version_id, is_applied) VALUES (999, true)`); err != nil {
		t.Fatal(err)
	}
	if v, err := db.Version(ctx, pool); err != nil || v != 999 {
		t.Fatalf("db.Version after concurrent insert = %d, err = %v, want 999 (the insert must be visible outside the snapshot)", v, err)
	}

	var after int64
	if err := tx.QueryRow(ctx, `SELECT version_id FROM goose_db_version WHERE is_applied ORDER BY id DESC LIMIT 1`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("snapshot saw version change from %d to %d; REPEATABLE READ should have hidden it", before, after)
	}
}

// TestServiceStreamSurvivesRootRewrapBetweenConstructionAndStream is the
// batch-4 review's Critical regression test. Before the fix, a
// backup.Service captured crypto.root's sealed bytes once (at
// construction, mirroring serve.go's old boot-time capture) and reused
// them in every archive's header; a KEK rewrap job re-sealing that same
// row under a newly active KEK — entirely independent of when any backup
// runs — left every later archive's header disagreeing with the row it
// actually dumped, and restoreLoad's byte-equality check rejected it with
// ErrTampered. This test rewraps the row (simulating what
// kek.RewrapWorker does during a KEK rotation, without needing the full
// rewrap job) strictly between constructing the Service and calling
// Stream, then proves the resulting archive still restores cleanly: Write
// now reads crypto.root live from its own snapshot (write.go's
// readRootSealed), so the header and the dumped settings.csv row always
// agree regardless of this timing.
func TestServiceStreamSurvivesRootRewrapBetweenConstructionAndStream(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)

	kekA, kekB := testKey(21), testKey(22)
	// envA: only KEK-A configured, the "boot-time" envelope a server
	// starts with before any rotation.
	envA := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(kekA), kekA))
	storeA := settings.NewStore(q, envA)
	root, err := storeA.EnsureRoot(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.EnsureCanary(ctx); err != nil {
		t.Fatal(err)
	}

	// Service construction: BaseKey is derived from the plaintext root
	// (rewrap-proof on its own, since rewrap never changes the plaintext)
	// — only the header's RootSealed used to be captured at this same
	// moment, which is exactly what this test proves no longer happens.
	svc := &backup.Service{
		Pool: pool, Settings: storeA,
		BaseKey: crypto.DeriveKey(root, "certforge-backup"), KEKID: envA.KEKID(), AppVersion: "test",
	}

	// Simulate a completed KEK rotation's rewrap: KEK-B is now active,
	// KEK-A kept as previous (matching a real post-rotation envelope), and
	// crypto.root is re-sealed under KEK-B — a fresh nonce/ciphertext for
	// the identical plaintext, exactly what kek.RewrapWorker would leave
	// behind, done directly here rather than through the full rewrap job.
	envB := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(kekB), kekB), crypto.NewStaticWrapper(crypto.KeyID(kekA), kekA))
	rewrapped, err := envB.Encrypt(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE settings SET secret = $1 WHERE key = $2`, rewrapped.Marshal(), settings.RootKey); err != nil {
		t.Fatal(err)
	}

	var archive bytes.Buffer
	if _, err := svc.Stream(ctx, &archive); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	dstPool := dbtest.Empty(t)
	restoreOpts := backup.RestoreOpts{
		Unseal: func(ctx context.Context, sealed []byte) ([]byte, error) {
			var blob crypto.Blob
			if err := blob.Unmarshal(sealed); err != nil {
				return nil, err
			}
			return envB.Decrypt(ctx, blob)
		},
		VerifyCanary: func(ctx context.Context, tx pgx.Tx) error {
			var raw []byte
			if err := tx.QueryRow(ctx, `SELECT secret FROM settings WHERE key = $1`, settings.CanaryKey).Scan(&raw); err != nil {
				return err
			}
			var blob crypto.Blob
			if err := blob.Unmarshal(raw); err != nil {
				return err
			}
			pt, err := envB.Decrypt(ctx, blob)
			if err != nil {
				return err
			}
			if !bytes.Equal(pt, crypto.CanaryPlaintext) {
				return settings.ErrCanaryMismatch
			}
			return nil
		},
	}
	if _, err := backup.Restore(ctx, dstPool, bytes.NewReader(archive.Bytes()), restoreOpts); err != nil {
		t.Fatalf("restore after a rewrap between Service construction and Stream: %v", err)
	}

	var restoredRoot []byte
	if err := dstPool.QueryRow(ctx, `SELECT secret FROM settings WHERE key = $1`, settings.RootKey).Scan(&restoredRoot); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restoredRoot, rewrapped.Marshal()) {
		t.Fatal("restored crypto.root does not match the rewrapped (KEK-B-sealed) row")
	}
}
