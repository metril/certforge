package api

import (
	"context"
	"encoding/csv"
	"errors"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

func TestCsvCell(t *testing.T) {
	cases := map[string]string{
		"":                "",
		"plain":           "plain",
		"=SUM(1+1)":       "'=SUM(1+1)",
		"+1":              "'+1",
		"-1":              "'-1",
		"@cmd":            "'@cmd",
		"\ttab":           "'\ttab",
		"\rcr":            "'\rcr",
		"safe=inside":     "safe=inside",
		"safe, comma":     "safe, comma",
		"safe \"quoted\"": "safe \"quoted\"",
	}
	for in, want := range cases {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}

// rowsFetcher fakes a keyset-paginated query: each call returns the next
// page (trimmed to the requested limit, like a real SQL LIMIT would), or an
// error on the call numbered errAt (a negative errAt never errors).
func rowsFetcher(pages [][]sqlcgen.ListAuditEventsRow, errAt int) auditRowFetcher {
	calls := 0
	return func(_ context.Context, _ int64, _ bool, limit int) ([]sqlcgen.ListAuditEventsRow, error) {
		defer func() { calls++ }()
		if calls == errAt {
			return nil, errors.New("boom")
		}
		if calls >= len(pages) {
			return nil, nil
		}
		p := pages[calls]
		if limit < len(p) {
			p = p[:limit]
		}
		return p, nil
	}
}

// TestWriteAuditCSVMidStreamError verifies a fetch failure partway through
// does not truncate the CSV silently: the rows already written stay, and a
// final "#error,<message>" row makes the file visibly incomplete instead of
// just stopping.
func TestWriteAuditCSVMidStreamError(t *testing.T) {
	page := []sqlcgen.ListAuditEventsRow{{ID: 1, Action: "a"}, {ID: 2, Action: "b"}}
	var buf strings.Builder
	// page (chunk) size == len(page) so the first fetch exactly fills its
	// requested limit; writeAuditCSV then assumes there may be more and
	// asks again, which is where rowsFetcher fails.
	writeAuditCSV(context.Background(), &buf, rowsFetcher([][]sqlcgen.ListAuditEventsRow{page}, 1), 100, len(page))
	r := csv.NewReader(strings.NewReader(buf.String()))
	r.FieldsPerRecord = -1 // the trailing #error row is shorter than a data row
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v\n%s", err, buf.String())
	}
	if len(rows) != 4 { // header + 2 data rows + error row
		t.Fatalf("rows = %d, want 4: %v", len(rows), rows)
	}
	last := rows[len(rows)-1]
	if last[0] != "#error" || last[1] != "boom" {
		t.Fatalf("last row = %v, want #error,boom", last)
	}
}

// TestWriteAuditCSVCap verifies the row cap is honored even when more rows
// are available.
func TestWriteAuditCSVCap(t *testing.T) {
	page := make([]sqlcgen.ListAuditEventsRow, 5)
	for i := range page {
		page[i] = sqlcgen.ListAuditEventsRow{ID: int64(i + 1), Action: "a"}
	}
	var buf strings.Builder
	writeAuditCSV(context.Background(), &buf, rowsFetcher([][]sqlcgen.ListAuditEventsRow{page, page, page}, -1), 12, len(page))
	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v\n%s", err, buf.String())
	}
	if len(rows) != 13 { // header + 12 rows, capped
		t.Fatalf("rows = %d, want 13: %v", len(rows), rows)
	}
}
