package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/crypto"
)

// WriteOpts configures Write.
type WriteOpts struct {
	// BaseKey is DeriveKey(root, "certforge-backup"), computed by the
	// caller from the unsealed root secret (Deviations R6: serve derives
	// this once and keeps it, deriving before clearing the root itself
	// from memory). Write never sees the plaintext root.
	BaseKey []byte
	// RootSealed is the raw crypto.root settings row (settings.SealedRoot):
	// a marshalled crypto.Blob, recorded in the header unchanged.
	RootSealed []byte
	// KEKID is the active envelope's KEK id, recorded as
	// Header.ActiveKEKID.
	KEKID string
	// PreviousKEKIDs is recorded as Header.PreviousKEKIDs.
	PreviousKEKIDs []string
	// AppVersion is recorded as Header.AppVersion.
	AppVersion string
}

// Summary is what Write produced.
type Summary struct {
	// SizeBytes is the total archive size written to w.
	SizeBytes int64
	// Tables is manifest.json's own content: one row per Manifest table.
	Tables []TableSum
}

// Write streams one full encrypted backup archive of pool to w: a single
// REPEATABLE READ, read-only transaction takes a consistent snapshot,
// records the schema version it sees, then dumps every Manifest table from
// that same snapshot as CSV, tarred and AES-256-GCM chunk-encrypted under a
// key derived from opts.BaseKey and a fresh per-archive salt. Concurrent
// writes to the database during the dump never appear half-included, and a
// migration that runs after the snapshot begins is not reflected in
// either the header's MigrationVersion or the dumped rows
// (TestWriteHeaderMatchesSnapshot).
func Write(ctx context.Context, pool *pgxpool.Pool, w io.Writer, opts WriteOpts) (Summary, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Summary{}, fmt.Errorf("backup: begin snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // read-only; always safe, no-op if never committed (it never is)

	version, err := snapshotVersion(ctx, tx)
	if err != nil {
		return Summary{}, err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return Summary{}, fmt.Errorf("backup: salt: %w", err)
	}
	streamKey := crypto.DeriveKey(opts.BaseKey, hex.EncodeToString(salt))

	header := Header{
		Format:           Format,
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
		AppVersion:       opts.AppVersion,
		MigrationVersion: version,
		ActiveKEKID:      opts.KEKID,
		PreviousKEKIDs:   opts.PreviousKEKIDs,
		RootSealed:       opts.RootSealed,
		Salt:             salt,
		Tables:           Manifest,
	}
	hjson, err := json.Marshal(header)
	if err != nil {
		return Summary{}, fmt.Errorf("backup: encode header: %w", err)
	}
	if len(hjson) > maxHeaderLen {
		return Summary{}, fmt.Errorf("backup: header too large: %d bytes", len(hjson))
	}

	cw := &countingWriter{w: w}
	if _, err := cw.Write([]byte(Magic)); err != nil {
		return Summary{}, fmt.Errorf("backup: write magic: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(hjson)))
	if _, err := cw.Write(lenBuf[:]); err != nil {
		return Summary{}, fmt.Errorf("backup: write header length: %w", err)
	}
	if _, err := cw.Write(hjson); err != nil {
		return Summary{}, fmt.Errorf("backup: write header: %w", err)
	}
	hh := headerHash([]byte(Magic), hjson)

	body, err := newChunkWriter(cw, streamKey, hh)
	if err != nil {
		return Summary{}, err
	}
	tw := tar.NewWriter(body)

	sums := make([]TableSum, 0, len(Manifest))
	for _, table := range Manifest {
		sum, err := dumpTable(ctx, tx, tw, table)
		if err != nil {
			return Summary{}, err
		}
		sums = append(sums, sum)
	}

	mjson, err := json.Marshal(manifestFile{Tables: sums})
	if err != nil {
		return Summary{}, fmt.Errorf("backup: encode manifest: %w", err)
	}
	if err := writeTarEntry(tw, "manifest.json", mjson); err != nil {
		return Summary{}, err
	}
	if err := tw.Close(); err != nil {
		return Summary{}, fmt.Errorf("backup: close tar: %w", err)
	}
	if err := body.Close(); err != nil {
		return Summary{}, fmt.Errorf("backup: close stream: %w", err)
	}

	return Summary{SizeBytes: cw.n, Tables: sums}, nil
}

// snapshotVersion reads the schema version tx's own REPEATABLE READ
// snapshot sees, rather than going through internal/db's goose provider
// (which would open its own connection and session, outside this
// transaction's snapshot).
func snapshotVersion(ctx context.Context, tx pgx.Tx) (int64, error) {
	var v int64
	err := tx.QueryRow(ctx, `SELECT version_id FROM goose_db_version WHERE is_applied ORDER BY id DESC LIMIT 1`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("backup: read migration version: %w", err)
	}
	return v, nil
}

// dumpTable copies table's non-generated columns to CSV (with a header
// row), hashes the exact bytes produced, and writes them as one tar entry
// named "<table>.csv". Row count comes from COPY's own command tag.
func dumpTable(ctx context.Context, tx pgx.Tx, tw *tar.Writer, table string) (TableSum, error) {
	cols, err := tableColumns(ctx, tx, table)
	if err != nil {
		return TableSum{}, err
	}

	selectList := make([]string, len(cols))
	for i, c := range cols {
		selectList[i] = pgx.Identifier{c}.Sanitize()
	}
	sql := fmt.Sprintf(`COPY (SELECT %s FROM %s) TO STDOUT (FORMAT csv, HEADER)`,
		strings.Join(selectList, ", "), pgx.Identifier{table}.Sanitize())

	var buf bytes.Buffer
	tag, err := tx.Conn().PgConn().CopyTo(ctx, &buf, sql)
	if err != nil {
		return TableSum{}, fmt.Errorf("backup: dump %s: %w", table, err)
	}

	sum := sha256.Sum256(buf.Bytes())
	if err := writeTarEntry(tw, table+".csv", buf.Bytes()); err != nil {
		return TableSum{}, err
	}
	return TableSum{Name: table, Rows: tag.RowsAffected(), SHA256: hex.EncodeToString(sum[:])}, nil
}

// tableColumns lists table's columns in ordinal order, excluding any
// generated column: a generated column's value is computed by Postgres
// from other columns, so it cannot appear in a COPY FROM's column list
// (COPY BINARY/TEXT FROM cannot target it) and must equally be left out of
// the COPY TO that produced the CSV in the first place, or dump and load
// would disagree on column count.
func tableColumns(ctx context.Context, tx pgx.Tx, table string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1 AND is_generated <> 'ALWAYS'
		ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, fmt.Errorf("backup: columns for %s: %w", table, err)
	}
	defer rows.Close()

	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("backup: columns for %s: %w", table, err)
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backup: columns for %s: %w", table, err)
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("backup: table %s: no columns found (unknown table?)", table)
	}
	return cols, nil
}

func writeTarEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(data)), Mode: 0600}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("backup: tar header %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("backup: tar write %s: %w", name, err)
	}
	return nil
}

// countingWriter tallies bytes written, for Summary.SizeBytes.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
