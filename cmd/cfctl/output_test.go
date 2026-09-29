package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestProblemRendering covers the exact "error: <title>: <detail>" line
// the task-13 contract requires, and the fallback when a problem body has
// no detail or fails to parse at all.
func TestProblemRendering(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{
			name:   "title and detail",
			status: 422,
			body:   `{"type":"about:blank","title":"Validation failed","status":422,"detail":"name is required"}`,
			want:   "error: Validation failed: name is required",
		},
		{
			name:   "title only",
			status: 403,
			body:   `{"type":"about:blank","title":"Forbidden","status":403}`,
			want:   "error: Forbidden",
		},
		{
			name:   "unparsable body falls back to status text",
			status: 401,
			body:   ``,
			want:   "error: Unauthorized",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := problemFromBody(c.status, []byte(c.body))
			if err.Error() != c.want {
				t.Fatalf("Error() = %q, want %q", err.Error(), c.want)
			}
			var pe *problemError
			if !errors.As(err, &pe) {
				t.Fatal("expected a *problemError")
			}
		})
	}
}

// TestFailPrintsProblemVerbatim covers fail's split: a *problemError is
// printed as-is, anything else gets the "cfctl: " prefix.
func TestFailPrintsProblemVerbatim(t *testing.T) {
	var stderr bytes.Buffer
	code := fail(&stderr, problemFromBody(404, []byte(`{"title":"Not Found","detail":"no such certificate"}`)))
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if got := strings.TrimSpace(stderr.String()); got != "error: Not Found: no such certificate" {
		t.Fatalf("stderr = %q", got)
	}

	stderr.Reset()
	code = fail(&stderr, errors.New("connection refused"))
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if got := strings.TrimSpace(stderr.String()); got != "cfctl: connection refused" {
		t.Fatalf("stderr = %q", got)
	}
}

// TestWriteTable covers the aligned-table default output mode.
func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	writeTable(&buf, []string{"ID", "NAME"}, [][]string{
		{"1", "alpha"}, {"2", "beta"},
	})
	out := buf.String()
	for _, want := range []string{"ID", "NAME", "1", "alpha", "2", "beta"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table output missing %q: %q", want, out)
		}
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected a header + 2 rows, got %d lines: %q", len(lines), out)
	}
}

// TestWriteFileAtomic covers the 0600 temp-then-rename write, and that a
// failed write (a directory that doesn't exist) leaves nothing behind.
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/out.bin"
	if err := writeFileAtomic(path, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("data = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly the written file, got %v", entries)
	}
}
