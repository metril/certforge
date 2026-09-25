package agent

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
