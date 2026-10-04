package agent

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/delivery"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestFileWriterAtomicModeAndReplace(t *testing.T) {
	dir := t.TempDir()
	w := &FileWriter{Log: discard, EUID: os.Geteuid(), Lookup: lookupIDs}
	p := filepath.Join(dir, "a", "b", "key.pem")
	if err := w.Write(p, []byte("one"), 0o640, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(p, []byte("two"), 0o600, "", ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "two" || mode(t, p) != 0o600 {
		t.Fatalf("content %q mode %v", b, mode(t, p))
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("temp files left: %v", entries)
	}
}

func TestFileWriterNonRootIgnoresOwnerOnce(t *testing.T) {
	var buf bytes.Buffer
	w := &FileWriter{Log: slog.New(slog.NewTextHandler(&buf, nil)), EUID: 1000,
		Lookup: func(string, string) (int, int, error) { t.Fatal("lookup as non-root"); return 0, 0, nil }}
	p := filepath.Join(t.TempDir(), "x.pem")
	for range 2 {
		if err := w.Write(p, []byte("x"), 0o640, "root", "ssl-cert"); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Count(buf.String(), "not running as root") != 1 {
		t.Fatalf("log %q", buf.String())
	}
}

func TestFileDigest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	if sum, _, err := fileDigest(p); err != nil || sum != "" {
		t.Fatalf("missing: %q %v", sum, err)
	}
	_ = os.WriteFile(p, []byte("abc"), 0o600)
	if sum, mt, err := fileDigest(p); err != nil || sum != delivery.Digest([]byte("abc")) || mt.IsZero() {
		t.Fatalf("present: %q %v", sum, err)
	}
}

func TestStageAtomicParentDirsAndSweep(t *testing.T) {
	root := t.TempDir()
	w := &FileWriter{Log: discard, EUID: os.Geteuid(), Lookup: lookupIDs}

	// New parent dirs are 0755 whatever the first file's mode, so a later
	// world-readable file in the same dir stays reachable; each file keeps
	// its own mode, and an existing dir is never chmod'ed.
	if err := w.Write(filepath.Join(root, "n", "key.pem"), []byte("k"), 0o600, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(filepath.Join(root, "n", "cert.pem"), []byte("c"), 0o644, "", ""); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{"n": 0o755, "n/key.pem": 0o600, "n/cert.pem": 0o644} {
		if got := mode(t, filepath.Join(root, p)); got != want {
			t.Errorf("%s mode %v, want %v", p, got, want)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "s"), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(filepath.Join(root, "s", "key.pem"), []byte("k"), 0o600, "", ""); err != nil {
		t.Fatal(err)
	}
	if got := mode(t, filepath.Join(root, "s")); got != 0o711 {
		t.Errorf("existing dir mode changed to %v", got)
	}

	// Stale temps are swept; fresh ones and other files' temps are kept.
	dir := filepath.Join(root, "s")
	stale := filepath.Join(dir, ".key.pem.tmp-111")
	fresh := filepath.Join(dir, ".key.pem.tmp-222")
	other := filepath.Join(dir, ".other.pem.tmp-333")
	for _, p := range []string{stale, fresh, other} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-time.Hour)
	for _, p := range []string{stale, other} {
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Write(filepath.Join(dir, "key.pem"), []byte("k2"), 0o600, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("stale temp survived")
	}
	for _, p := range []string{fresh, other} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s removed: %v", p, err)
		}
	}
}
