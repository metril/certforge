package importer

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func readAllFile(t *testing.T, fsys fs.FS, name string) string {
	t.Helper()
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestExtractArchive covers both formats ExtractArchive supports.
func TestExtractArchive(t *testing.T) {
	t.Run("zip", func(t *testing.T) {
		data := buildZip(t, map[string]string{"a/b.txt": "hello", "a/c.txt": "world"})
		fsys, err := ExtractArchive(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if got := readAllFile(t, fsys, "a/b.txt"); got != "hello" {
			t.Fatalf("a/b.txt = %q", got)
		}
		if got := readAllFile(t, fsys, "a/c.txt"); got != "world" {
			t.Fatalf("a/c.txt = %q", got)
		}
	})
	t.Run("targz", func(t *testing.T) {
		data := buildTarGz(t, map[string]string{"x/y.txt": "one", "x/z.txt": "two"})
		fsys, err := ExtractArchive(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if got := readAllFile(t, fsys, "x/y.txt"); got != "one" {
			t.Fatalf("x/y.txt = %q", got)
		}
		if got := readAllFile(t, fsys, "x/z.txt"); got != "two" {
			t.Fatalf("x/z.txt = %q", got)
		}
	})
}

// TestExtractArchiveRejects covers every guard: zip-slip, an absolute
// path, too many entries, too much uncompressed data (streamed, not
// trusting the header), a symlink being skipped rather than extracted, and
// a stream that is neither zip nor gzip.
func TestExtractArchiveRejects(t *testing.T) {
	t.Run("zip slip", func(t *testing.T) {
		data := buildZip(t, map[string]string{"../evil.txt": "x"})
		if _, err := ExtractArchive(bytes.NewReader(data)); !errors.Is(err, ErrArchive) {
			t.Fatalf("err = %v, want ErrArchive", err)
		}
	})
	t.Run("absolute path", func(t *testing.T) {
		data := buildZip(t, map[string]string{"/etc/passwd": "x"})
		if _, err := ExtractArchive(bytes.NewReader(data)); !errors.Is(err, ErrArchive) {
			t.Fatalf("err = %v, want ErrArchive", err)
		}
	})
	t.Run("too many entries", func(t *testing.T) {
		files := make(map[string]string, maxEntries+1)
		for i := 0; i < maxEntries+1; i++ {
			files["f"+strconv.Itoa(i)+".txt"] = "x"
		}
		data := buildZip(t, files)
		if _, err := ExtractArchive(bytes.NewReader(data)); !errors.Is(err, ErrArchive) {
			t.Fatalf("err = %v, want ErrArchive", err)
		}
	})
	t.Run("too large streamed", func(t *testing.T) {
		// readWithinBudget counts the actual bytes read.LimitReader off the
		// entry, never hdr.Size, so this only needs an entry whose real
		// content exceeds the budget; the header is accurate (archive/tar
		// itself refuses to write more than Size bytes for an entry, so a
		// literally lying header cannot be built through the stdlib
		// writer).
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		big := bytes.Repeat([]byte{'a'}, maxUncompressedBytes+1)
		hdr := &tar.Header{Name: "big.bin", Mode: 0o644, Size: int64(len(big)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(big); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := ExtractArchive(bytes.NewReader(buf.Bytes())); !errors.Is(err, ErrArchive) {
			t.Fatalf("err = %v, want ErrArchive", err)
		}
	})
	t.Run("symlink skipped", func(t *testing.T) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		if err := tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}); err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(&tar.Header{Name: "real.txt", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("real")); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
		fsys, err := ExtractArchive(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fs.Stat(fsys, "link"); err == nil {
			t.Fatal("symlink entry was extracted, want it skipped")
		}
		if got := readAllFile(t, fsys, "real.txt"); got != "real" {
			t.Fatalf("real.txt = %q", got)
		}
	})
	t.Run("plain text", func(t *testing.T) {
		if _, err := ExtractArchive(strings.NewReader("not an archive")); !errors.Is(err, ErrArchive) {
			t.Fatalf("err = %v, want ErrArchive", err)
		}
	})
}
