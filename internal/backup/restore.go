package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/settings"
)

// minMigrationVersion is migration 00013, the first version whose foreign
// keys are all DEFERRABLE (Deviations R6): Restore never targets anything
// older, whatever an older archive's own header says.
const minMigrationVersion = 13

// RestoreOpts configures Restore. Both funcs run against the caller's own
// configured envelope (active plus any previous KEK); Restore itself never
// constructs one, so it has no way to unseal anything on its own.
type RestoreOpts struct {
	// Unseal decrypts header.RootSealed (a marshalled crypto.Blob) under
	// the caller's envelope. Failure — a KEK id the caller does not have,
	// or an authentication failure — is reported as ErrKEKMismatch before
	// Restore has touched the database at all.
	Unseal func(ctx context.Context, sealed []byte) ([]byte, error)
	// VerifyCanary opens settings.CanaryKey under tx — Restore's own load
	// transaction, so it sees rows Restore just loaded but has not yet
	// committed — and returns a non-nil error if it does not decrypt to
	// crypto.CanaryPlaintext under the caller's envelope.
	VerifyCanary func(ctx context.Context, tx pgx.Tx) error
}

// Restore loads archive r into pool.
//
// It first unseals header.RootSealed with opts.Unseal: failure means the
// configured KEK does not match this backup (ErrKEKMismatch) and nothing
// is written. It then checks the target database is not already migrated
// past max(header.MigrationVersion, minMigrationVersion) (ErrNewerDatabase),
// migrates up to exactly that version (db.MigrateTo, so a restore never
// races ahead to this binary's own latest schema before loading), and
// loads every Manifest table (goose_db_version excepted — the migrator
// owns it) plus river_job inside one transaction with foreign keys
// deferred. Row counts and content hashes are checked against the
// archive's own manifest.json; a mismatch, a missing table or an
// unreadable chunk is ErrTampered. Before commit, the freshly loaded
// crypto.root must equal header.RootSealed byte for byte and the canary
// must open under the caller's envelope (opts.VerifyCanary) — either
// failure rolls back the whole transaction, so a crafted or foreign
// archive can never leave the database partially loaded. On success,
// db.Migrate brings the schema the rest of the way to this binary's own
// latest version.
func Restore(ctx context.Context, pool *pgxpool.Pool, r io.Reader, opts RestoreOpts) (Header, error) {
	header, headerHash, err := readHeader(r)
	if err != nil {
		return Header{}, err
	}

	rootPT, err := opts.Unseal(ctx, header.RootSealed)
	if err != nil {
		return Header{}, fmt.Errorf("%w: %w", ErrKEKMismatch, err)
	}
	defer clear(rootPT)

	target := header.MigrationVersion
	if target < minMigrationVersion {
		target = minMigrationVersion
	}
	current, err := db.Version(ctx, pool)
	if err != nil {
		return Header{}, fmt.Errorf("backup: read database version: %w", err)
	}
	if current > target {
		return Header{}, fmt.Errorf("%w: database is at version %d, this backup targets %d", ErrNewerDatabase, current, target)
	}
	if err := db.MigrateTo(ctx, pool, target); err != nil {
		return Header{}, fmt.Errorf("backup: migrate to %d: %w", target, err)
	}

	baseKey := crypto.DeriveKey(rootPT, "certforge-backup")
	streamKey := crypto.DeriveKey(baseKey, hex.EncodeToString(header.Salt))

	if err := restoreLoad(ctx, pool, r, header, headerHash, streamKey, opts); err != nil {
		return Header{}, err
	}

	if err := db.Migrate(ctx, pool); err != nil {
		return Header{}, fmt.Errorf("backup: migrate to latest: %w", err)
	}
	return header, nil
}

// restoreLoad runs the whole truncate-and-reload inside one transaction,
// rolling back on any error (including a deferred func running after an
// early return, and the explicit rollback-on-verification-failure paths
// below — both reach the same tx.Rollback).
func restoreLoad(ctx context.Context, pool *pgxpool.Pool, r io.Reader, header Header, headerHash, streamKey []byte, opts RestoreOpts) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("backup: begin restore: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() // no-op once committed

	if _, err := tx.Exec(ctx, "SET CONSTRAINTS ALL DEFERRED"); err != nil {
		return fmt.Errorf("backup: defer constraints: %w", err)
	}

	loadTables := make([]string, 0, len(Manifest)-1)
	for _, t := range Manifest {
		if t != "goose_db_version" {
			loadTables = append(loadTables, t)
		}
	}
	if err := truncateForRestore(ctx, tx, loadTables); err != nil {
		return err
	}

	cr, err := newChunkReader(r, streamKey, headerHash)
	if err != nil {
		return err
	}
	tr := tar.NewReader(cr)

	seen := map[string]TableSum{}
	var manifestSums map[string]TableSum
	for {
		hdr, err := tr.Next()
		if err == io.EOF { //nolint:errorlint // archive/tar documents io.EOF as the exact end-of-archive sentinel
			break
		}
		if err != nil {
			return fmt.Errorf("%w: tar: %w", ErrTampered, err)
		}

		if hdr.Name == "manifest.json" {
			data, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("%w: manifest.json: %w", ErrTampered, err)
			}
			var mf manifestFile
			if err := json.Unmarshal(data, &mf); err != nil {
				return fmt.Errorf("%w: manifest.json: %w", ErrTampered, err)
			}
			manifestSums = make(map[string]TableSum, len(mf.Tables))
			for _, s := range mf.Tables {
				manifestSums[s.Name] = s
			}
			continue
		}

		table, ok := strings.CutSuffix(hdr.Name, ".csv")
		if !ok {
			return fmt.Errorf("%w: unexpected tar entry %q", ErrTampered, hdr.Name)
		}
		// goose_db_version is dumped and hash-checked like every other
		// table, but never loaded — the migrator (db.MigrateTo, already
		// run above) owns that table entirely (contract details, Restore).
		sum, err := loadTable(ctx, tx, tr, table, table != "goose_db_version")
		if err != nil {
			return err
		}
		seen[table] = sum
	}

	if manifestSums == nil {
		return fmt.Errorf("%w: archive has no manifest.json", ErrTampered)
	}
	if err := verifyManifest(header.Tables, seen, manifestSums); err != nil {
		return err
	}

	if err := resetSequences(ctx, tx, loadTables); err != nil {
		return err
	}

	var restoredRoot []byte
	if err := tx.QueryRow(ctx, `SELECT secret FROM settings WHERE key = $1`, settings.RootKey).Scan(&restoredRoot); err != nil {
		return fmt.Errorf("%w: read restored root: %w", ErrTampered, err)
	}
	if !bytes.Equal(restoredRoot, header.RootSealed) {
		return fmt.Errorf("%w: restored crypto.root does not match the archive header", ErrTampered)
	}

	if err := opts.VerifyCanary(ctx, tx); err != nil {
		return fmt.Errorf("%w: canary: %w", ErrTampered, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("backup: commit restore: %w", err)
	}
	return nil
}

// truncateForRestore clears every table about to be reloaded, plus
// river_job (a restore replaces the rows any queued job might point at, so
// a stale job must not survive it — Deviations R6). audit_events is
// deliberately excluded: its own triggers (00001_init.sql,
// audit_events_no_truncate) refuse TRUNCATE unconditionally, by design —
// the append-only hash chain must never be erasable, not even by a
// restore. Its rows are still loaded below, as plain inserts (COPY FROM,
// never blocked by that trigger), on top of whatever the target database
// already had.
func truncateForRestore(ctx context.Context, tx pgx.Tx, tables []string) error {
	idents := make([]string, 0, len(tables)+1)
	for _, t := range tables {
		if t == "audit_events" {
			continue
		}
		idents = append(idents, pgx.Identifier{t}.Sanitize())
	}
	idents = append(idents, pgx.Identifier{"river_job"}.Sanitize())
	sql := fmt.Sprintf("TRUNCATE %s CASCADE", strings.Join(idents, ", "))
	if _, err := tx.Exec(ctx, sql); err != nil {
		return fmt.Errorf("backup: truncate: %w", err)
	}
	return nil
}

// loadTable reads one "<table>.csv" tar entry (a Postgres COPY ... HEADER
// dump: a header row naming its columns, then data rows) and, if load is
// true, replays it with COPY <table> (<those columns>) FROM STDIN — the
// entry's own header line, not the live schema's current column order, is
// the source of truth for the column list (contract details). Every byte
// of the entry is hashed either way, so goose_db_version (load=false) is
// still covered by the manifest comparison.
func loadTable(ctx context.Context, tx pgx.Tx, tr *tar.Reader, table string, load bool) (TableSum, error) {
	hasher := sha256.New()
	br := bufio.NewReader(io.TeeReader(tr, hasher))

	headerLine, err := br.ReadString('\n')
	if err != nil {
		return TableSum{}, fmt.Errorf("%w: %s: csv header: %w", ErrTampered, table, err)
	}
	cols := strings.Split(strings.TrimRight(headerLine, "\r\n"), ",")
	if len(cols) == 0 || (len(cols) == 1 && cols[0] == "") {
		return TableSum{}, fmt.Errorf("%w: %s: empty csv header", ErrTampered, table)
	}

	var rows int64
	if load {
		colList := make([]string, len(cols))
		for i, c := range cols {
			colList[i] = pgx.Identifier{c}.Sanitize()
		}
		sql := fmt.Sprintf(`COPY %s (%s) FROM STDIN (FORMAT csv, HEADER)`,
			pgx.Identifier{table}.Sanitize(), strings.Join(colList, ", "))
		body := io.MultiReader(strings.NewReader(headerLine), br)
		tag, err := tx.Conn().PgConn().CopyFrom(ctx, body, sql)
		if err != nil {
			return TableSum{}, fmt.Errorf("%w: load %s: %w", ErrTampered, table, err)
		}
		rows = tag.RowsAffected()
	} else if _, err := io.Copy(io.Discard, br); err != nil {
		return TableSum{}, fmt.Errorf("%w: %s: %w", ErrTampered, table, err)
	}

	return TableSum{Name: table, Rows: rows, SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

// verifyManifest checks that the archive covers exactly this binary's
// Manifest, that every table was present in the tar, and that each one's
// hash (and, except for goose_db_version whose row count Restore never
// itself counts, row count) matches manifest.json.
func verifyManifest(headerTables []string, seen, manifestSums map[string]TableSum) error {
	if !slices.Equal(headerTables, Manifest) {
		return fmt.Errorf("%w: archive's table list does not match this build's manifest", ErrTampered)
	}
	for _, t := range Manifest {
		s, ok := seen[t]
		if !ok {
			return fmt.Errorf("%w: archive is missing table %s", ErrTampered, t)
		}
		m, ok := manifestSums[t]
		if !ok {
			return fmt.Errorf("%w: manifest.json is missing table %s", ErrTampered, t)
		}
		if s.SHA256 != m.SHA256 {
			return fmt.Errorf("%w: table %s: content hash mismatch", ErrTampered, t)
		}
		if t != "goose_db_version" && s.Rows != m.Rows {
			return fmt.Errorf("%w: table %s: row count mismatch (loaded %d, manifest %d)", ErrTampered, t, s.Rows, m.Rows)
		}
	}
	return nil
}

// resetSequences sets every owned sequence among tables to one past its
// column's current maximum, since COPY FROM loads explicit primary key
// values without advancing the sequence that normally supplies them
// (contract details: "sequences owned by manifest columns are reset to
// max+1").
func resetSequences(ctx context.Context, tx pgx.Tx, tables []string) error {
	for _, t := range tables {
		cols, err := serialColumns(ctx, tx, t)
		if err != nil {
			return err
		}
		for _, c := range cols {
			sql := fmt.Sprintf(
				`SELECT setval(pg_get_serial_sequence('public.'||$1, $2), COALESCE((SELECT max(%s) FROM %s), 0) + 1, false)`,
				pgx.Identifier{c}.Sanitize(), pgx.Identifier{t}.Sanitize())
			if _, err := tx.Exec(ctx, sql, t, c); err != nil {
				return fmt.Errorf("backup: reset sequence %s.%s: %w", t, c, err)
			}
		}
	}
	return nil
}

func serialColumns(ctx context.Context, tx pgx.Tx, table string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1 AND column_default LIKE 'nextval(%'`, table)
	if err != nil {
		return nil, fmt.Errorf("backup: serial columns for %s: %w", table, err)
	}
	defer rows.Close()

	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("backup: serial columns for %s: %w", table, err)
		}
		cols = append(cols, c)
	}
	return cols, rows.Err()
}
