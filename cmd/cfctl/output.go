package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/metril/certforge/internal/api/client"
)

// timeFormat is used for every human-readable timestamp column.
const timeFormat = "2006-01-02T15:04:05Z"

// problemError is a parsed RFC 9457 problem+json body, rendered the way
// every cfctl command reports a server-side failure.
type problemError struct {
	title  string
	detail string
}

// Error renders "error: <title>: <detail>" (or "error: <title>" when the
// problem carried no detail), the exact line the task-13 contract requires.
func (e *problemError) Error() string {
	if e.detail == "" {
		return "error: " + e.title
	}
	return "error: " + e.title + ": " + e.detail
}

// problemFromBody parses body as a client.Problem. A body that fails to
// parse (an empty 401, a proxy error page) falls back to the HTTP status
// text so a command always reports something readable rather than an
// empty title.
func problemFromBody(status int, body []byte) error {
	var p client.Problem
	if len(body) > 0 {
		_ = json.Unmarshal(body, &p)
	}
	if p.Title == "" {
		p.Title = http.StatusText(status)
		if p.Title == "" {
			p.Title = fmt.Sprintf("HTTP %d", status)
		}
	}
	detail := ""
	if p.Detail != nil {
		detail = *p.Detail
	}
	return &problemError{title: p.Title, detail: detail}
}

// fail reports err to stderr and returns the exit code 1 every command
// error uses. A *problemError is printed as-is ("error: <title>:
// <detail>"); anything else (a network failure, a decode error) is
// prefixed "cfctl: ".
func fail(stderr io.Writer, err error) int {
	var pe *problemError
	if errors.As(err, &pe) {
		fmt.Fprintln(stderr, pe.Error())
		return 1
	}
	fmt.Fprintf(stderr, "cfctl: %v\n", err)
	return 1
}

// writeTable renders rows as an aligned table with a header, cfctl's
// default (non-JSON) output mode.
func writeTable(w io.Writer, header []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	tw.Flush()
}

// writeFileAtomic writes data to a temp file beside path, mode 0600 (the
// default for os.CreateTemp), and renames it onto path on success. A
// reader never observes a partially written file, and a failed write
// leaves nothing at the final name.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cfctl-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
