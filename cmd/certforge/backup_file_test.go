package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.cfbak")

	// A planted symlink at the old fixed temp name must not be followed.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, func(w io.Writer) error { _, err := w.Write([]byte("archive")); return err }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("victim overwritten: %q", b)
	}
	if b, _ := os.ReadFile(path); string(b) != "archive" {
		t.Fatalf("archive = %q", b)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", st.Mode().Perm())
	}

	// A failing writer leaves neither the target changed nor a temp behind.
	boom := errors.New("boom")
	if err := writeFileAtomic(path, func(io.Writer) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "archive" {
		t.Fatalf("archive changed: %q", b)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != "out.cfbak" && e.Name() != "victim" && e.Name() != "out.cfbak.tmp" {
			t.Fatalf("leftover %s", e.Name())
		}
	}
}
