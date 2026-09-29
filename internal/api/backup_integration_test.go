//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/backup"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/settings"
)

// backupTestKey is the same fixed static KEK newTestEnvOpts uses internally
// (testenv_integration_test.go), reused here (same convention as
// issuance_fixture_integration_test.go) so a test that needs the real
// envelope — decrypting RootSealed for a restore round trip — can build an
// equal one without newTestEnvOpts exposing its own.
var backupTestKey = bytes.Repeat([]byte{7}, 32)

// withBackup returns a newTestEnvOpts option wiring d.Backup from d's own
// already-constructed Settings/Pool/Auditor/Log (set before opts run): the
// real root secret and its sealed form, so backup.Service.Stream produces
// a genuinely restorable archive.
func withBackup(t *testing.T) func(*api.Deps) {
	t.Helper()
	return func(d *api.Deps) {
		ctx := context.Background()
		root, err := d.Settings.EnsureRoot(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := d.Settings.SealedRoot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Settings.EnsureCanary(ctx); err != nil {
			t.Fatal(err)
		}
		d.Backup = &backup.Service{
			Pool: d.Pool, Settings: d.Settings, Audit: d.Auditor, Log: d.Log,
			BaseKey: crypto.DeriveKey(root, "certforge-backup"), RootSealed: sealed,
			KEKID: crypto.KeyID(backupTestKey), AppVersion: "test",
		}
	}
}

// setBackupSettings writes the "backup" section directly through the
// store (bypassing PUT /settings/backup's own schema validation, which
// checkBackupDirectory would otherwise enforce for a real directory) —
// createBackup and the schedule job read this section live.
func setBackupSettings(t *testing.T, e *testEnv, set backup.Settings) {
	t.Helper()
	if err := e.deps.Settings.Set(context.Background(), settings.SectionKey("backup"), set); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) auditCount(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := e.deps.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestCreateBackupRequiresEscrow: createBackup refuses with 409 while the
// backup section's kekEscrowConfirmed is off (the section's own default),
// and never streams a byte.
func TestCreateBackupRequiresEscrow(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	csrf, _ := e.seedAdminSession()

	resp, body := e.do(http.MethodPost, "/api/v1/backup", nil, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if n := e.auditCount(t, "backup.created"); n != 0 {
		t.Fatalf("backup.created audit count = %d, want 0", n)
	}
}

// TestCreateBackupStreamsAndAudits: needs settings:write (403 for a
// viewer), streams a valid archive with the right headers once escrow is
// confirmed, audits backup.created {sizeBytes}, and updates the shared
// status row (LastSuccessAt/LastSizeBytes move, LastFile stays null — an
// on-demand backup is never written to disk).
func TestCreateBackupStreamsAndAudits(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	csrf, org := e.seedAdminSession()
	setBackupSettings(t, e, backup.Settings{KEKEscrowConfirmed: true, Schedule: "off", RetainCount: 7})

	viewerClient, viewerCsrf, _ := e.userSession("viewer1", "viewer", &org)
	resp, body := e.doClient(viewerClient, http.MethodPost, "/api/v1/backup", nil, http.Header{authn.CSRFHeader: {viewerCsrf}}) //nolint:bodyclose // testEnv.doClient closes the body
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer status = %d, body = %s", resp.StatusCode, body)
	}

	resp, body = e.do(http.MethodPost, "/api/v1/backup", nil, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content-type = %q", ct)
	}
	cd := resp.Header.Get("Content-Disposition")
	if !strings.HasPrefix(cd, `attachment; filename="certforge-`) || !strings.HasSuffix(cd, `.cfbak"`) {
		t.Fatalf("content-disposition = %q", cd)
	}
	hdr, err := backup.ReadHeader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("archive header: %v", err)
	}
	if hdr.Format != backup.Format {
		t.Fatalf("format = %q", hdr.Format)
	}

	if n := e.auditCount(t, "backup.created"); n != 1 {
		t.Fatalf("backup.created audit count = %d", n)
	}

	statusResp, statusBody := e.do(http.MethodGet, "/api/v1/backup/status", nil, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status endpoint = %d, body = %s", statusResp.StatusCode, statusBody)
	}
	var st struct {
		EscrowConfirmed bool    `json:"escrowConfirmed"`
		LastSuccessAt   *string `json:"lastSuccessAt"`
		LastSizeBytes   *int64  `json:"lastSizeBytes"`
		LastFile        *string `json:"lastFile"`
	}
	if err := json.Unmarshal(statusBody, &st); err != nil {
		t.Fatal(err)
	}
	if !st.EscrowConfirmed || st.LastSuccessAt == nil || st.LastSizeBytes == nil || *st.LastSizeBytes == 0 {
		t.Fatalf("status = %+v", st)
	}
	if st.LastFile != nil {
		t.Fatalf("LastFile = %v, want null for an on-demand backup", *st.LastFile)
	}
}

// TestCreateBackupMidStreamErrorAborts: a Stream failure after headers are
// already on the wire (Service.StreamFunc writes a few genuine bytes, then
// fails) truncates the connection outright — the client's read fails with
// an unexpected EOF, not a clean body — and no backup.created audit is
// ever recorded.
func TestCreateBackupMidStreamErrorAborts(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	csrf, _ := e.seedAdminSession()
	setBackupSettings(t, e, backup.Settings{KEKEscrowConfirmed: true, Schedule: "off", RetainCount: 7})
	e.deps.Backup.StreamFunc = func(_ context.Context, w io.Writer) (backup.Summary, error) {
		// net/http buffers small writes and drops them unflushed on an
		// ErrAbortHandler panic (they never reach the socket), so the
		// client would see a bare connection failure instead of a
		// genuinely truncated body. Writing well past that buffer forces
		// a real flush of headers and partial body first, matching the
		// brief's "a failing Stream after the first [64 KiB] chunk".
		if _, err := w.Write(bytes.Repeat([]byte{0}, 256*1024)); err != nil {
			return backup.Summary{}, err
		}
		return backup.Summary{}, errors.New("simulated mid-stream failure")
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, e.srv.URL+"/api/v1/backup", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(authn.CSRFHeader, csrf)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	_, err = io.ReadAll(resp.Body)
	if err == nil {
		t.Fatal("expected the body read to fail (aborted mid-stream), got a clean read")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read error = %v, want io.ErrUnexpectedEOF", err)
	}

	if n := e.auditCount(t, "backup.created"); n != 0 {
		t.Fatalf("backup.created audit count = %d, want 0", n)
	}
}

// TestBackupAPIRestoreRoundTrip: the archive createBackup streams over
// HTTP restores cleanly into a fresh database (same counts, canary
// verified — Restore itself fails otherwise).
func TestBackupAPIRestoreRoundTrip(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	csrf, org := e.seedAdminSession()
	setBackupSettings(t, e, backup.Settings{KEKEscrowConfirmed: true, Schedule: "off", RetainCount: 7})
	if _, err := e.deps.Pool.Exec(context.Background(),
		`INSERT INTO sites (org_id, name) VALUES ($1, 'site1')`, org); err != nil {
		t.Fatal(err)
	}

	resp, body := e.do(http.MethodPost, "/api/v1/backup", nil, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(backupTestKey), backupTestKey))
	dst := dbtest.Empty(t)
	ctx := context.Background()
	_, err := backup.Restore(ctx, dst, bytes.NewReader(body), backup.RestoreOpts{
		Unseal: func(ctx context.Context, sealed []byte) ([]byte, error) {
			var blob crypto.Blob
			if err := blob.Unmarshal(sealed); err != nil {
				return nil, err
			}
			return env.Decrypt(ctx, blob)
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
			pt, err := env.Decrypt(ctx, blob)
			if err != nil {
				return err
			}
			if !bytes.Equal(pt, crypto.CanaryPlaintext) {
				return settings.ErrCanaryMismatch
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	var srcOrgs, dstOrgs int
	if err := e.deps.Pool.QueryRow(ctx, `SELECT count(*) FROM orgs`).Scan(&srcOrgs); err != nil {
		t.Fatal(err)
	}
	if err := dst.QueryRow(ctx, `SELECT count(*) FROM orgs`).Scan(&dstOrgs); err != nil {
		t.Fatal(err)
	}
	if srcOrgs != dstOrgs || srcOrgs == 0 {
		t.Fatalf("orgs: src=%d dst=%d", srcOrgs, dstOrgs)
	}
	var siteName string
	if err := dst.QueryRow(ctx, `SELECT name FROM sites WHERE name = 'site1'`).Scan(&siteName); err != nil {
		t.Fatalf("restored site missing: %v", err)
	}
}

// TestScheduledBackupEmitsEvent: RunScheduled, run directly against a real
// database and directory, writes a retained file and records a status the
// API reports, without going through the hourly river job itself (the
// river wiring is exercised by RegisterRiver's own use in
// cmd/certforge/serve.go, not re-tested here).
func TestScheduledBackupEmitsEvent(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	dir := t.TempDir()
	setBackupSettings(t, e, backup.Settings{KEKEscrowConfirmed: true, Schedule: "daily", RetainCount: 7, Directory: dir})

	if err := e.deps.Backup.RunScheduled(context.Background()); err != nil {
		t.Fatalf("RunScheduled: %v", err)
	}

	entries, err := readDirNames(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasPrefix(entries[0], "certforge-") || !strings.HasSuffix(entries[0], ".cfbak") {
		t.Fatalf("directory entries = %v", entries)
	}

	st, err := e.deps.Backup.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.LastSuccessAt == nil || st.LastFile != entries[0] || st.LastSizeBytes == nil {
		t.Fatalf("status = %+v", st)
	}

	// Running again immediately must no-op: the daily cadence isn't due yet.
	if err := e.deps.Backup.RunScheduled(context.Background()); err != nil {
		t.Fatalf("RunScheduled (second run): %v", err)
	}
	entries2, err := readDirNames(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries2) != 1 {
		t.Fatalf("second immediate run wrote another file: %v", entries2)
	}
}

func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
