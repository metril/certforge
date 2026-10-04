//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/backup"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/settings"
)

// fakeBackupEventInserter is notify.Inserter backed by memory — the same
// shape monitor_fixture_integration_test.go's own fakeMonitorEventInserter
// uses, redefined here since that one lives in the white-box "api"
// package, not "api_test". Emit's own notification_events/
// notification_deliveries rows are real SQL writes regardless of which
// Inserter backs the (never actually queued in these tests) river
// delivery job.
type fakeBackupEventInserter struct{}

func (fakeBackupEventInserter) InsertTx(_ context.Context, _ pgx.Tx, _ river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}}, nil
}

// backupTestKey is the same fixed static KEK newTestEnvOpts uses internally
// (testenv_integration_test.go), reused here (same convention as
// issuance_fixture_integration_test.go) so a test that needs the real
// envelope — decrypting RootSealed for a restore round trip — can build an
// equal one without newTestEnvOpts exposing its own.
var backupTestKey = bytes.Repeat([]byte{7}, 32)

// withBackup returns a newTestEnvOpts option wiring d.Backup from d's own
// already-constructed Settings/Pool/Auditor/Log (set before opts run): the
// real root secret, so backup.Service.Stream produces a genuinely
// restorable archive (Write itself reads the sealed crypto.root row live,
// from its own snapshot — batch-4 review — so this fixture no longer
// captures one). Emitter is a real notify.Emitter against d's own Pool
// (fakeBackupEventInserter only stands in for the river delivery job —
// Emit's own notification_events/notification_deliveries rows are real
// SQL writes either way), so TestScheduledBackupEmitsEvent and
// TestScheduledBackupFailureRecordsEventAuditAndBackoff (batch-4 review)
// can assert on the actual event rows a scheduled run raises.
func withBackup(t *testing.T) func(*api.Deps) {
	t.Helper()
	return func(d *api.Deps) {
		ctx := context.Background()
		root, err := d.Settings.EnsureRoot(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Settings.EnsureCanary(ctx); err != nil {
			t.Fatal(err)
		}
		d.Backup = &backup.Service{
			Pool: d.Pool, Settings: d.Settings, Audit: d.Auditor, Log: d.Log,
			Emitter: &notify.Emitter{Pool: d.Pool, River: fakeBackupEventInserter{}, Log: d.Log},
			BaseKey: crypto.DeriveKey(root, "certforge-backup"),
			KEKID:   crypto.KeyID(backupTestKey), AppVersion: "test",
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

// TestCreateBackupRunsWithDefaultSettings: createBackup needs no
// confirmation: with the backup section never saved it still streams an
// archive and audits backup.created.
func TestCreateBackupRunsWithDefaultSettings(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	csrf, _ := e.seedAdminSession()

	resp, body := e.do(http.MethodPost, "/api/v1/backup", nil, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %.200s", resp.StatusCode, body)
	}
	if n := e.auditCount(t, "backup.created"); n != 1 {
		t.Fatalf("backup.created audit count = %d, want 1", n)
	}
}

// TestCreateBackupStreamsAndAudits: needs settings:write (403 for a
// viewer), streams a valid archive with the right headers with no
// confirmation needed, audits backup.created {sizeBytes}, and updates the shared
// status row (LastSuccessAt/LastSizeBytes move, LastFile stays null — an
// on-demand backup is never written to disk).
func TestCreateBackupStreamsAndAudits(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	csrf, org := e.seedAdminSession()
	setBackupSettings(t, e, backup.Settings{Schedule: "off", RetainCount: 7})

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
		LastSuccessAt *string `json:"lastSuccessAt"`
		LastSizeBytes *int64  `json:"lastSizeBytes"`
		LastFile      *string `json:"lastFile"`
	}
	if err := json.Unmarshal(statusBody, &st); err != nil {
		t.Fatal(err)
	}
	if st.LastSuccessAt == nil || st.LastSizeBytes == nil || *st.LastSizeBytes == 0 {
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
	setBackupSettings(t, e, backup.Settings{Schedule: "off", RetainCount: 7})
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
	d := waitBackupFailed(t, e)
	if d["trigger"] != "on_demand" || d["error"] != "simulated mid-stream failure" || d["reason"] != nil {
		t.Fatalf("backup.failed details = %v", d)
	}
}

// waitBackupFailed polls for the backup.failed audit row (written by the
// stream goroutine, after the client has already seen the abort).
func waitBackupFailed(t *testing.T, e *testEnv) map[string]any {
	t.Helper()
	for i := 0; i < 100; i++ {
		var raw []byte
		err := e.deps.Pool.QueryRow(context.Background(), `SELECT details FROM audit_events WHERE action = 'backup.failed' ORDER BY id DESC LIMIT 1`).Scan(&raw)
		if err == nil {
			var d map[string]any
			if json.Unmarshal(raw, &d) != nil {
				t.Fatalf("details %s", raw)
			}
			return d
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no backup.failed audit row")
	return nil
}

// A client that goes away mid-stream is recorded as client_aborted, not a
// server failure (the request context is already cancelled by then).
func TestCreateBackupClientAbortAudited(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	csrf, _ := e.seedAdminSession()
	setBackupSettings(t, e, backup.Settings{Schedule: "off", RetainCount: 7})
	e.deps.Backup.StreamFunc = func(ctx context.Context, w io.Writer) (backup.Summary, error) {
		if _, err := w.Write(bytes.Repeat([]byte{0}, 256*1024)); err != nil {
			return backup.Summary{}, err
		}
		<-ctx.Done()
		return backup.Summary{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.srv.URL+"/api/v1/backup", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(authn.CSRFHeader, csrf)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = resp.Body.Close()
	d := waitBackupFailed(t, e)
	if d["trigger"] != "on_demand" || d["reason"] != "client_aborted" {
		t.Fatalf("backup.failed details = %v", d)
	}
}

// TestBackupAPIRestoreRoundTrip: the archive createBackup streams over
// HTTP restores cleanly into a fresh database (same counts, canary
// verified — Restore itself fails otherwise).
func TestBackupAPIRestoreRoundTrip(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	csrf, org := e.seedAdminSession()
	setBackupSettings(t, e, backup.Settings{Schedule: "off", RetainCount: 7})
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
// database and directory, writes a retained file, records a status the API
// reports, and raises backup.completed with the file's own dedupe key
// (batch-4 review: asserted against the real notification_events row, not
// just "no event" against a nil Emitter) — without going through the
// hourly river job itself (the river wiring is exercised by
// RegisterRiver's own use in cmd/certforge/serve.go, not re-tested here).
func TestScheduledBackupEmitsEvent(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	dir := t.TempDir()
	setBackupSettings(t, e, backup.Settings{Schedule: "daily", RetainCount: 7, Directory: dir})

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

	wantDedupe := "backup.completed:" + entries[0]
	kind, dedupe := e.notificationEvent(t, wantDedupe)
	if kind != "backup.completed" || dedupe != wantDedupe {
		t.Fatalf("event kind/dedupe = %q/%q, want backup.completed/%q", kind, dedupe, wantDedupe)
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

// TestScheduledBackupFailureRecordsEventAuditAndBackoff (batch-4 review):
// a due run against an unwritable directory (here, one whose parent does
// not exist — portable across a root-run test container, unlike a chmod
// 0000 directory a root process would simply ignore) fails at
// os.OpenFile, and the failure is recorded on every surface the contract
// promises: Status's lastFailureAt/lastError, a backup.failed audit row
// (system actor), a backup.failed notification event, and — the 1 h
// backoff — a second immediate run does not retry (no new audit row, no
// new event, lastFailureAt unchanged).
func TestScheduledBackupFailureRecordsEventAuditAndBackoff(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	badDir := "/nonexistent-" + t.Name() + "/backups"
	setBackupSettings(t, e, backup.Settings{Schedule: "daily", RetainCount: 7, Directory: badDir})

	if err := e.deps.Backup.RunScheduled(context.Background()); err != nil {
		t.Fatalf("RunScheduled: %v", err)
	}

	st, err := e.deps.Backup.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.LastFailureAt == nil || st.LastError == "" {
		t.Fatalf("status = %+v, want a recorded failure", st)
	}
	firstFailureAt := *st.LastFailureAt

	if n := e.auditCount(t, "backup.failed"); n != 1 {
		t.Fatalf("backup.failed audit count = %d, want 1", n)
	}

	kind, dedupe := e.notificationEventByKind(t, "backup.failed")
	if kind != "backup.failed" || !strings.HasPrefix(dedupe, "backup.failed:") {
		t.Fatalf("event kind/dedupe = %q/%q", kind, dedupe)
	}

	// The 1 h backoff: a second immediate run must not retry.
	if err := e.deps.Backup.RunScheduled(context.Background()); err != nil {
		t.Fatalf("RunScheduled (second run): %v", err)
	}
	if n := e.auditCount(t, "backup.failed"); n != 1 {
		t.Fatalf("backup.failed audit count after a second immediate run = %d, want still 1 (1 h backoff)", n)
	}
	st2, err := e.deps.Backup.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st2.LastFailureAt == nil || !st2.LastFailureAt.Equal(firstFailureAt) {
		t.Fatalf("lastFailureAt changed on a second immediate run: %v -> %v (want unchanged, 1 h backoff)", firstFailureAt, st2.LastFailureAt)
	}
}

// TestOnDemandBackupDoesNotPostponeSchedule (final review fix wave,
// finding 2, service.go:118/schedule.go:68): RecordOnDemandSuccess used to
// move the same LastSuccessAt due()/nextAt schedule off of, so any
// on-demand download (API or cfctl) pushed the next scheduled backup
// further out — a daily download meant the scheduled directory never got
// a file at all. A separate lastScheduledAt, touched only by the
// scheduled path, must be what due()/nextAt read.
func TestOnDemandBackupDoesNotPostponeSchedule(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	dir := t.TempDir()
	setBackupSettings(t, e, backup.Settings{Schedule: "daily", RetainCount: 7, Directory: dir})

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e.deps.Backup.Now = func() time.Time { return base }

	if err := e.deps.Backup.RunScheduled(context.Background()); err != nil {
		t.Fatalf("RunScheduled: %v", err)
	}
	st1, err := e.deps.Backup.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantNext := base.Add(24 * time.Hour)
	if st1.NextAt == nil || !st1.NextAt.Equal(wantNext) {
		t.Fatalf("NextAt after the scheduled run = %v, want %v", st1.NextAt, wantNext)
	}

	// An on-demand download completes later the same day.
	later := base.Add(6 * time.Hour)
	e.deps.Backup.Now = func() time.Time { return later }
	if err := e.deps.Backup.RecordOnDemandSuccess(context.Background(), 999); err != nil {
		t.Fatal(err)
	}

	st2, err := e.deps.Backup.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st2.NextAt == nil || !st2.NextAt.Equal(wantNext) {
		t.Fatalf("NextAt after the on-demand download = %v, want unchanged %v (an on-demand download must not postpone the schedule)", st2.NextAt, wantNext)
	}
	if st2.LastSuccessAt == nil || !st2.LastSuccessAt.Equal(later) {
		t.Fatalf("LastSuccessAt after the on-demand download = %v, want %v", st2.LastSuccessAt, later)
	}
}

// TestScheduledSuccessSaveIsAtomicWithConcurrentStatusWrites (final review
// fix wave, finding 2, schedule.go:68): runOnce loads its own status
// snapshot before the (possibly slow) Stream call and, on success, used to
// save that whole snapshot back — a write landing on backup.status while
// Stream is still running (here, on a field this scheduled run's own
// success path never itself sets) must survive runOnce's own save once it
// finally completes, not get blindly overwritten by the stale pre-Stream
// snapshot.
func TestScheduledSuccessSaveIsAtomicWithConcurrentStatusWrites(t *testing.T) {
	e := newTestEnvOpts(t, withBackup(t))
	dir := t.TempDir()
	setBackupSettings(t, e, backup.Settings{Schedule: "daily", RetainCount: 7, Directory: dir})

	wantFailure := time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC)
	e.deps.Backup.StreamFunc = func(ctx context.Context, w io.Writer) (backup.Summary, error) {
		// A concurrent write lands on backup.status mid-stream, on
		// lastFailureAt — a field this run's own (upcoming) success save
		// never itself sets. No row for this key exists yet at this point
		// (this is the very first backup attempt), hence INSERT ... ON
		// CONFLICT rather than a plain UPDATE.
		if _, err := e.deps.Pool.Exec(ctx,
			`INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::jsonb, now())
			 ON CONFLICT (key) DO UPDATE SET value = COALESCE(settings.value, '{}'::jsonb) || EXCLUDED.value, updated_at = now()`,
			"backup.status", fmt.Sprintf(`{"lastFailureAt":%q}`, wantFailure.Format(time.RFC3339))); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("x")); err != nil {
			return backup.Summary{}, err
		}
		return backup.Summary{SizeBytes: 1}, nil
	}

	if err := e.deps.Backup.RunScheduled(context.Background()); err != nil {
		t.Fatalf("RunScheduled: %v", err)
	}

	st, err := e.deps.Backup.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.LastFailureAt == nil || !st.LastFailureAt.Equal(wantFailure) {
		t.Fatalf("LastFailureAt = %v, want %v (a concurrent write mid-stream must survive the scheduled run's own success save)", st.LastFailureAt, wantFailure)
	}
	if st.LastFile == "" || st.LastSuccessAt == nil {
		t.Fatalf("status = %+v, want the scheduled run's own success recorded too", st)
	}
}

// notificationEvent looks up one notification_events row by its exact
// dedupe key, failing the test if it is missing.
func (e *testEnv) notificationEvent(t *testing.T, dedupeKey string) (kind, dedupe string) {
	t.Helper()
	err := e.deps.Pool.QueryRow(context.Background(),
		`SELECT kind, dedupe_key FROM notification_events WHERE dedupe_key = $1`, dedupeKey).Scan(&kind, &dedupe)
	if err != nil {
		t.Fatalf("notification_events dedupe_key=%q: %v", dedupeKey, err)
	}
	return kind, dedupe
}

// notificationEventByKind looks up the (expected single) notification_events
// row of the given kind, failing the test if it is missing.
func (e *testEnv) notificationEventByKind(t *testing.T, kind string) (gotKind, dedupe string) {
	t.Helper()
	err := e.deps.Pool.QueryRow(context.Background(),
		`SELECT kind, dedupe_key FROM notification_events WHERE kind = $1`, kind).Scan(&gotKind, &dedupe)
	if err != nil {
		t.Fatalf("notification_events kind=%q: %v", kind, err)
	}
	return gotKind, dedupe
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
