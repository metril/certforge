package metrics

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

// TestSnapshotNegativeCachesFailure: a failed refresh is logged and counts
// as a refresh, so scrapes inside CacheTTL do not retry the database; the
// next attempt happens once CacheTTL has elapsed.
func TestSnapshotNegativeCachesFailure(t *testing.T) {
	// Lazy pool against a closed port: every query fails fast.
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/db?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	var buf bytes.Buffer
	now := time.Unix(1_000_000, 0)
	c := &Collector{q: sqlcgen.New(pool), pool: pool, log: slog.New(slog.NewTextHandler(&buf, nil)),
		now: func() time.Time { return now }}

	c.snapshot()
	c.snapshot()
	if n := strings.Count(buf.String(), "metrics refresh failed"); n != 1 {
		t.Fatalf("failures logged within CacheTTL = %d, want 1 (second scrape must not retry)", n)
	}
	now = now.Add(CacheTTL)
	c.snapshot()
	if n := strings.Count(buf.String(), "metrics refresh failed"); n != 2 {
		t.Fatalf("failures logged after CacheTTL = %d, want 2", n)
	}
}
