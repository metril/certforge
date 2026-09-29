//go:build integration

package backup_test

import (
	"context"
	"testing"

	"github.com/metril/certforge/internal/backup"
	"github.com/metril/certforge/internal/db/dbtest"
)

// TestManifestCoversAllTables is the standing check that backup.Manifest
// stays exactly information_schema's non-river tables (goose_db_version
// included) as later phases add more. A table that exists but is missing
// from Manifest would silently never be backed up or restored; a Manifest
// entry with no matching table would make Write fail outright the moment
// it tried to dump it.
func TestManifestCoversAllTables(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)

	rows, err := pool.Query(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
		  AND table_name NOT LIKE 'river\_%' ESCAPE '\'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	got := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		got[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{}
	for _, name := range backup.Manifest {
		want[name] = true
	}

	for name := range got {
		if !want[name] {
			t.Errorf("table %q exists in the schema but is missing from backup.Manifest", name)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("backup.Manifest lists %q but it does not exist in the schema", name)
		}
	}
}
