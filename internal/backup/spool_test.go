package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpoolDefaultsToOSTempDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	backupDir := t.TempDir()
	sp, err := newSpool("")
	if err != nil {
		t.Fatal(err)
	}
	defer sp.close()
	if filepath.Dir(sp.dir) != tmp || !strings.HasPrefix(filepath.Base(sp.dir), spoolPrefix) {
		t.Fatalf("spool dir %q not under %q", sp.dir, tmp)
	}
	if entries, _ := os.ReadDir(backupDir); len(entries) != 0 {
		t.Fatalf("backup dir not empty: %v", entries)
	}
	if fi, err := os.Stat(sp.dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("spool dir mode: %v %v", fi, err)
	}
}

func TestSpoolDirOptionRedirects(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	custom := t.TempDir()
	sp, err := newSpool(custom)
	if err != nil {
		t.Fatal(err)
	}
	defer sp.close()
	if filepath.Dir(sp.dir) != custom {
		t.Fatalf("spool dir %q not under %q", sp.dir, custom)
	}
	dir := sp.dir
	sp.close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("spool dir not removed: %v", err)
	}
}

func TestSpoolUnusableDirErrors(t *testing.T) {
	if _, err := newSpool(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("newSpool of a missing dir succeeded")
	}
}

// TestSweepSkipsLockedSpool: an old spool whose lock a live backup holds
// survives the sweep; an old unlocked one is removed.
func TestSweepSkipsLockedSpool(t *testing.T) {
	base := t.TempDir()
	live, err := newSpool(base)
	if err != nil {
		t.Fatal(err)
	}
	defer live.close()
	dead := filepath.Join(base, spoolPrefix+"dead")
	if err := os.Mkdir(dead, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dead, spoolLockName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	for _, d := range []string{live.dir, dead} {
		if err := os.Chtimes(d, old, old); err != nil {
			t.Fatal(err)
		}
	}
	sweepSpools(base)
	if _, err := os.Stat(live.dir); err != nil {
		t.Fatalf("locked spool removed: %v", err)
	}
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Fatalf("unlocked old spool kept: %v", err)
	}
}
