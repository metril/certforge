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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/settings"
)

// WriteOpts configures Write.
type WriteOpts struct {
	// BaseKey is DeriveKey(root, "certforge-backup"), computed by the
	// caller from the unsealed root secret (Deviations R6: serve derives
	// this once and keeps it, deriving before clearing the root itself
	// from memory). Write never sees the plaintext root.
	BaseKey []byte
	// KEKID is the active envelope's KEK id, recorded as
	// Header.ActiveKEKID.
	KEKID string
	// PreviousKEKIDs is recorded as Header.PreviousKEKIDs.
	PreviousKEKIDs []string
	// AppVersion is recorded as Header.AppVersion.
	AppVersion string
	// SpoolDir is where each table's plaintext CSV is staged (a private
	// 0700 subdirectory is created inside it) while its size and hash are
	// computed. Empty means the OS temp dir. If no spool can be created
	// there, Write logs a warning and buffers each table in memory instead,
	// so a backup never fails because of the spool. Never default this to
	// the backup directory: the spool is unencrypted.
	SpoolDir string
}

// spoolPrefix names the private spool directories; stale ones (a crashed
// run) are removed at the start of the next backup.
const spoolPrefix = ".certforge-spool-"

// spoolStaleAfter is how old an untouched spool directory must be before a
// new backup treats it as abandoned (a live backup touches its directory
// at every table); a held lock protects it regardless of age.
const spoolStaleAfter = time.Hour

// spoolLockName is the lock file inside each spool directory.
const spoolLockName = ".lock"

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

	rootSealed, err := readRootSealed(ctx, tx)
	if err != nil {
		return Summary{}, err
	}
	return writeTx(ctx, tx, w, opts, rootSealed)
}

// readRootSealed reads the crypto.root settings row from within tx —
// batch-4 review, Critical: a value captured outside this snapshot (at
// serve boot, or once before BEGIN in the CLI) can go stale the moment a
// KEK rewrap re-seals the row, since rewrap runs as its own periodic job
// independent of any backup. Reading it live, inside the exact same
// REPEATABLE READ snapshot the "settings" table itself is dumped from,
// guarantees Header.RootSealed and the dumped settings.csv row always
// agree by construction, for any KEK rotation/rewrap timing.
func readRootSealed(ctx context.Context, tx pgx.Tx) ([]byte, error) {
	var sealed []byte
	if err := tx.QueryRow(ctx, `SELECT secret FROM settings WHERE key = $1`, settings.RootKey).Scan(&sealed); err != nil {
		return nil, fmt.Errorf("backup: read root: %w", err)
	}
	return sealed, nil
}

// writeTx is Write's implementation once the snapshot transaction and the
// header's rootSealed are both already resolved. It is split out from
// Write so write_restore_integration_test.go's
// TestRestoreRootMismatchRollsBack can pass a deliberately wrong
// rootSealed — simulating a hand-crafted or buggy archive, independent of
// Write's own (now-guaranteed-consistent) behavior — to prove
// restoreLoad's own root check is real defense in depth, not merely an
// assumption Write happens to uphold.
func writeTx(ctx context.Context, tx pgx.Tx, w io.Writer, opts WriteOpts, rootSealed []byte) (Summary, error) {
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
		RootSealed:       rootSealed,
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

	spool, err := newSpool(opts.SpoolDir)
	if err != nil {
		slog.Warn("backup: spool directory unusable, buffering tables in memory", "err", err)
		spool = nil
	} else {
		defer spool.close()
	}

	sums := make([]TableSum, 0, len(Manifest))
	for _, table := range Manifest {
		sum, err := dumpTable(ctx, tx, tw, spool, table)
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

// spool is a private 0700 directory holding one table's plaintext CSV at a
// time. It holds an exclusive lock on its ".lock" file for its life so a
// concurrent backup's stale sweep never removes a live spool.
type spool struct {
	dir  string
	lock *os.File
}

// newSpool removes stale spool directories left by an interrupted backup,
// then creates a fresh private one under base (the OS temp dir when empty).
func newSpool(base string) (*spool, error) {
	if base == "" {
		base = os.TempDir()
	}
	sweepSpools(base)
	dir, err := os.MkdirTemp(base, spoolPrefix+"*")
	if err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, spoolLockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err == nil {
		err = lockFile(lock)
	}
	if err != nil {
		if lock != nil {
			_ = lock.Close()
		}
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &spool{dir: dir, lock: lock}, nil
}

// sweepSpools removes spool directories in base that are older than
// spoolStaleAfter and whose lock is not held by a live backup.
func sweepSpools(base string) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), spoolPrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) <= spoolStaleAfter {
			continue
		}
		dir := filepath.Join(base, e.Name())
		if held, f := lockHeld(filepath.Join(dir, spoolLockName)); !held {
			_ = os.RemoveAll(dir)
			if f != nil {
				_ = f.Close()
			}
		}
	}
}

func (s *spool) close() {
	_ = os.RemoveAll(s.dir)
	_ = s.lock.Close()
}

// dumpTable copies table's non-generated columns to CSV (with a header
// row) into a spool file, hashing the exact bytes produced, then streams
// the file into the tar as one entry named "<table>.csv" (size known from
// the spool). Row count comes from COPY's own command tag. The spool file is
// removed before return on every path.
func dumpTable(ctx context.Context, tx pgx.Tx, tw *tar.Writer, sp *spool, table string) (TableSum, error) {
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

	if sp == nil {
		return dumpTableMem(ctx, tx, tw, table, sql)
	}
	f, err := os.OpenFile(filepath.Join(sp.dir, table+".csv"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return TableSum{}, fmt.Errorf("backup: spool %s: %w", table, err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()

	h := sha256.New()
	cw := &countingWriter{w: io.MultiWriter(f, h)}
	tag, err := tx.Conn().PgConn().CopyTo(ctx, cw, sql)
	if err != nil {
		return TableSum{}, fmt.Errorf("backup: dump %s: %w", table, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return TableSum{}, fmt.Errorf("backup: spool %s: %w", table, err)
	}

	name := table + ".csv"
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: cw.n, Mode: 0600}); err != nil {
		return TableSum{}, fmt.Errorf("backup: tar header %s: %w", name, err)
	}
	if _, err := io.CopyN(tw, f, cw.n); err != nil {
		return TableSum{}, fmt.Errorf("backup: tar write %s: %w", name, err)
	}
	return TableSum{Name: table, Rows: tag.RowsAffected(), SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// dumpTableMem is dumpTable's fallback when no spool directory is usable:
// the whole CSV is buffered in memory.
func dumpTableMem(ctx context.Context, tx pgx.Tx, tw *tar.Writer, table, sql string) (TableSum, error) {
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
