// Package backup implements CertForge's pure-Go encrypted backup archive
// format: a REPEATABLE READ snapshot dump of every application table,
// written as an AES-256-GCM encrypted, chunked stream (Write), and a
// verified, transactional restore (Restore). See docs/internals/adr/0018 for the
// design and docs/guide/backup.md#backup for the operator-facing format.
package backup

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Format identifies this archive layout, recorded in every Header and
// checked by ReadHeader.
const Format = "certforge-backup-v1"

// Magic is the fixed byte string every archive starts with.
const Magic = "CFBAK1\n"

// ChunkSize is the maximum plaintext size of one encrypted chunk.
const ChunkSize = 64 << 10

// maxHeaderLen bounds the plaintext header's JSON encoding, so a corrupt or
// hostile length prefix can never make ReadHeader allocate an unbounded
// buffer.
const maxHeaderLen = 64 << 10

var (
	// ErrTampered means the archive's bytes do not match what Write
	// produced: a flipped byte, a truncated or reordered chunk, a
	// mismatched manifest hash or row count, or a restored crypto.root
	// that does not equal the header's.
	ErrTampered = errors.New("backup: archive tampered or truncated")
	// ErrKEKMismatch means the configured KEK (active or previous) cannot
	// unseal header.RootSealed, or the canary does not open under it after
	// loading: the archive was sealed under a different KEK than the one
	// this server (or this restore) is configured with.
	ErrKEKMismatch = errors.New("backup: KEK does not match this backup")
	// ErrNewerDatabase means the target database has already been
	// migrated past what this archive (and this binary's own minimum,
	// migration 13) declares, so Restore cannot safely reload it.
	ErrNewerDatabase = errors.New("backup: database schema is newer than this backup supports")
	// ErrAuditConflict means the target database already holds audit
	// events the archive also carries. audit_events is append-only and is
	// never truncated by a restore, so the archive's rows collide with it.
	ErrAuditConflict = errors.New("backup: target database already has audit events from this backup; restore into a fresh database")
)

// Header is the archive's plaintext preamble: readable (ReadHeader) without
// any key, so a caller can identify a backup and check its KEK id before
// deciding whether to unseal or load anything.
type Header struct {
	// Format is always the Format constant; ReadHeader rejects anything
	// else.
	Format string `json:"format"`
	// CreatedAt is when Write ran, RFC 3339 in UTC.
	CreatedAt string `json:"createdAt"`
	// AppVersion is the certforge build that produced this archive.
	AppVersion string `json:"appVersion"`
	// MigrationVersion is the schema version Write's snapshot transaction
	// observed (internal/db's goose_db_version at BEGIN time).
	MigrationVersion int64 `json:"migrationVersion"`
	// ActiveKEKID is the KEK id RootSealed and every other sealed column
	// in the dump were sealed under at backup time.
	ActiveKEKID string `json:"activeKekId"`
	// PreviousKEKIDs lists any other KEK ids the server also accepted at
	// backup time (a rotation in progress), recorded for the operator's
	// own reference; Restore only ever needs to unseal RootSealed itself.
	PreviousKEKIDs []string `json:"previousKekIds"`
	// RootSealed is the raw crypto.root settings row (settings.SealedRoot):
	// a marshalled crypto.Blob. Restore unseals this under its configured
	// envelope before writing anything (ErrKEKMismatch on failure), and
	// after loading, checks the restored settings row equals this exactly.
	RootSealed []byte `json:"rootSealed"`
	// Salt is 16 random bytes, unique per archive, mixed into the stream
	// key derivation so two backups of the same root never reuse a key.
	Salt []byte `json:"salt"`
	// Tables lists every table name Write dumped, in Manifest order.
	Tables []string `json:"tables"`
}

// ReadHeader reads and parses the plaintext header from the start of an
// archive. It performs no decryption and needs no key.
func ReadHeader(r io.Reader) (Header, error) {
	h, _, err := readHeader(r)
	return h, err
}

// readHeader is ReadHeader's implementation, also returning
// sha256(Magic‖headerJSON): the chunk stream's AAD binds every chunk to
// this exact header, so a header byte flip is caught the moment the first
// chunk is opened (TestArchiveTamperDetected), not silently accepted.
func readHeader(r io.Reader) (Header, []byte, error) {
	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return Header{}, nil, fmt.Errorf("%w: magic: %w", ErrTampered, err)
	}
	if string(magic) != Magic {
		return Header{}, nil, fmt.Errorf("%w: bad magic", ErrTampered)
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return Header{}, nil, fmt.Errorf("%w: header length: %w", ErrTampered, err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxHeaderLen {
		return Header{}, nil, fmt.Errorf("%w: header length %d exceeds %d", ErrTampered, n, maxHeaderLen)
	}

	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return Header{}, nil, fmt.Errorf("%w: header: %w", ErrTampered, err)
	}

	var h Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return Header{}, nil, fmt.Errorf("%w: header json: %w", ErrTampered, err)
	}
	if h.Format != Format {
		return Header{}, nil, fmt.Errorf("%w: unknown format %q", ErrTampered, h.Format)
	}

	hash := headerHash(magic, raw)
	return h, hash, nil
}
