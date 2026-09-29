package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/backup"
)

func TestRunHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"help"}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "version") {
		t.Fatalf("usage missing commands: %q", out.String())
	}
}

func TestRunNoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), nil, &out, &errOut); code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

func TestRunUnknown(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"nope"}, &out, &errOut); code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), `unknown command "nope"`) {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if out.String() != "dev\n" {
		t.Fatalf("out = %q", out.String())
	}
}

func TestBackupRequiresOut(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"backup"}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "--out is required") {
		t.Fatalf("errOut = %q", errOut.String())
	}
}

func TestRestoreRequiresIn(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"restore", "--yes"}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "--in is required") {
		t.Fatalf("errOut = %q", errOut.String())
	}
}

// fakeArchiveHeaderBytes builds the plaintext preamble backup.ReadHeader
// parses (Magic, a 4-byte big-endian length, then the header JSON) without
// needing a real database or KEK: TestRestoreWithoutYesExits2 only reaches
// the header-read path, never the encrypted body.
func fakeArchiveHeaderBytes(t *testing.T, h backup.Header) []byte {
	t.Helper()
	h.Format = backup.Format
	hjson, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	buf.WriteString(backup.Magic)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(hjson)))
	buf.Write(lenBuf[:])
	buf.Write(hjson)
	return buf.Bytes()
}

// TestRestoreWithoutYesExits2 covers the CLI row's confirmation step:
// without --yes, restore reads and prints the archive's plaintext header
// and exits 2, never touching a database (no CF_DATABASE_URL is set).
func TestRestoreWithoutYesExits2(t *testing.T) {
	stdin = bytes.NewReader(fakeArchiveHeaderBytes(t, backup.Header{
		CreatedAt: "2026-09-29T00:00:00Z", AppVersion: "test", MigrationVersion: 13, ActiveKEKID: "static-deadbeef",
	}))
	defer func() { stdin = nil }()

	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"restore", "--in", "-"}, &out, &errOut); code != 2 {
		t.Fatalf("code = %d, stderr = %q", code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("errOut = %q, want empty (exit 2 is informational, not an error)", errOut.String())
	}
	if !strings.Contains(out.String(), "migrationVersion=13") || !strings.Contains(out.String(), "activeKekId=static-deadbeef") {
		t.Fatalf("out = %q", out.String())
	}
}

// TestRestoreWithoutYesRejectsTamperedHeader covers the same path with an
// archive whose header cannot even be parsed: it still exits without a
// database, but as an ordinary error (code 1), not the confirmation exit.
func TestRestoreWithoutYesRejectsTamperedHeader(t *testing.T) {
	stdin = bytes.NewReader([]byte("not an archive"))
	defer func() { stdin = nil }()

	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"restore", "--in", "-"}, &out, &errOut); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}
