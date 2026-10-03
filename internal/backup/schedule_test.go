package backup

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestScheduleDue covers due's table (task-12 brief): off never runs;
// daily/weekly run once their own cadence has elapsed since the last
// success (or immediately with no success yet); a recent failure blocks a
// run regardless of how overdue the cadence otherwise is.
func TestScheduleDue(t *testing.T) {
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	hoursAgo := func(h int) *time.Time { t := now.Add(-time.Duration(h) * time.Hour); return &t }

	cases := []struct {
		name        string
		schedule    string
		lastSuccess *time.Time
		lastFailure *time.Time
		want        bool
	}{
		{"off never runs even with no success", "off", nil, nil, false},
		{"off never runs even when overdue", "off", hoursAgo(48), nil, false},
		{"daily with no prior success runs immediately", "daily", nil, nil, true},
		{"daily not yet due", "daily", hoursAgo(10), nil, false},
		{"daily exactly due", "daily", hoursAgo(24), nil, true},
		{"daily overdue", "daily", hoursAgo(48), nil, true},
		{"weekly with no prior success runs immediately", "weekly", nil, nil, true},
		{"weekly not yet due", "weekly", hoursAgo(24 * 3), nil, false},
		{"weekly exactly due", "weekly", hoursAgo(24 * 7), nil, true},
		{"weekly overdue", "weekly", hoursAgo(24 * 10), nil, true},
		{"recent failure blocks an otherwise-due daily run", "daily", hoursAgo(48), hoursAgo(0), false},
		{"failure within the backoff window blocks", "daily", nil, hoursAgo(0), false},
		{"failure past the backoff window no longer blocks", "daily", nil, hoursAgo(2), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := due(c.schedule, c.lastSuccess, c.lastFailure, now); got != c.want {
				t.Fatalf("due(%q, %v, %v) = %v, want %v", c.schedule, c.lastSuccess, c.lastFailure, got, c.want)
			}
		})
	}
}

// TestRetentionPrunesOldest seeds a directory with more certforge-*.cfbak
// files than retainCount and checks prune keeps exactly the
// lexicographically (== chronologically, given the fixed-width timestamp
// name) newest ones, ignoring unrelated files.
func TestRetentionPrunesOldest(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"certforge-20260101T000000Z.cfbak",
		"certforge-20260102T000000Z.cfbak",
		"certforge-20260103T000000Z.cfbak",
		"certforge-20260104T000000Z.cfbak",
		"certforge-20260105T000000Z.cfbak",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// An unrelated file must survive untouched.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := prune(dir, 2); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	want := []string{"certforge-20260104T000000Z.cfbak", "certforge-20260105T000000Z.cfbak", "readme.txt"}
	if len(got) != len(want) {
		t.Fatalf("remaining files = %v, want %v", got, want)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected %q to remain, got %v", w, got)
		}
	}
}

// TestRetentionKeepsAllWhenUnderLimit: retainCount above the file count is
// a no-op, not an error.
func TestRetentionKeepsAllWhenUnderLimit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "certforge-20260101T000000Z.cfbak"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prune(dir, 7); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %v, want 1 file kept", entries)
	}
}

// TestPruneRemovesStaleTmp: an orphaned .cfbak.tmp older than an hour is
// removed, a fresh one (a run in progress) is kept, and neither counts
// toward retention.
func TestPruneRemovesStaleTmp(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "certforge-20260101T000000Z.cfbak.tmp")
	fresh := filepath.Join(dir, "certforge-20260102T000000Z.cfbak.tmp")
	keep := filepath.Join(dir, "certforge-20260103T000000Z.cfbak")
	for _, p := range []string{stale, fresh, keep} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := prune(dir, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale tmp still present: %v", err)
	}
	for _, p := range []string{fresh, keep} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s removed: %v", p, err)
		}
	}
}

func TestSyncDir(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("syncDir: %v", err)
	}
	if err := syncDir(filepath.Join(t.TempDir(), "missing")); err == nil && runtime.GOOS != "windows" {
		t.Fatal("syncDir of a missing dir succeeded")
	}
}
