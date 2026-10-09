// Package certstore stores certificate versions: leaf and chain DER plus the
// envelope-encrypted PKCS#8 key.
package certstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/signer"
)

// ErrNotFound means no such version for the certificate.
var ErrNotFound = errors.New("certificate version not found")

// Version is version metadata (no key material).
type Version struct {
	ID, CertID          uuid.UUID
	Serial              string
	NotBefore, NotAfter time.Time
	SHA256              string // hex of the leaf DER
	KeyType, Source     string
	HasKey              bool
	CAID                *uuid.UUID
	RevokedAt           *time.Time
	CreatedAt           time.Time
}

// InsertOpts records a stored version's provenance: how it entered
// CertForge (issued, imported, or uploaded) and, when known, which CA it
// was issued or last renewed against (used by the rate ledger).
type InsertOpts struct {
	Source string // issued, imported, uploaded
	CAID   *uuid.UUID
}

// Store reads and writes certificate_versions.
type Store struct {
	q   *sqlcgen.Queries
	box crypto.Box
}

// WithQueries returns a Store reading through q (a transaction's queries).
func (s *Store) WithQueries(q *sqlcgen.Queries) *Store {
	return &Store{q: q, box: s.box}
}

// WithTx returns a Store whose queries run in tx.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx), box: s.box}
}

// New returns a Store.
func New(pool *pgxpool.Pool, box crypto.Box) *Store {
	return &Store{q: sqlcgen.New(pool), box: box}
}

// Insert stores issued, imported, or uploaded material inside tx. An empty
// (nil or zero-length) iss.PrivateKeyPKCS8 stores no key (a keyless
// version); o.Source defaults to "issued" when empty.
func (s *Store) Insert(ctx context.Context, tx pgx.Tx, certID uuid.UUID, iss *signer.Issued, keyType string, o InsertOpts) (Version, error) {
	var sealed []byte
	if len(iss.PrivateKeyPKCS8) > 0 {
		var err error
		if sealed, err = s.box.Seal(ctx, iss.PrivateKeyPKCS8); err != nil {
			return Version{}, err
		}
	}
	fp := sha256.Sum256(iss.LeafDER)
	chain := iss.ChainDER
	if chain == nil {
		chain = [][]byte{}
	}
	source := o.Source
	if source == "" {
		source = "issued"
	}
	r, err := s.q.WithTx(tx).InsertCertificateVersion(ctx, sqlcgen.InsertCertificateVersionParams{
		CertID: certID, Serial: iss.Serial, NotBefore: iss.NotBefore, NotAfter: iss.NotAfter,
		Sha256Fp: hex.EncodeToString(fp[:]), KeyType: keyType, LeafDer: iss.LeafDER, ChainDer: chain,
		PrivateKey: sealed, Source: source, CaID: o.CAID,
	})
	if err != nil {
		return Version{}, err
	}
	return Version{ID: r.ID, CertID: r.CertID, Serial: r.Serial, NotBefore: r.NotBefore, NotAfter: r.NotAfter,
		SHA256: r.Sha256Fp, KeyType: r.KeyType, Source: r.Source, HasKey: r.HasKey, CAID: r.CaID,
		RevokedAt: r.RevokedAt, CreatedAt: r.CreatedAt}, nil
}

// List returns a certificate's versions, newest first.
func (s *Store) List(ctx context.Context, certID uuid.UUID) ([]Version, error) {
	rows, err := s.q.ListCertificateVersions(ctx, certID)
	if err != nil {
		return nil, err
	}
	out := make([]Version, len(rows))
	for i, r := range rows {
		out[i] = Version{ID: r.ID, CertID: r.CertID, Serial: r.Serial, NotBefore: r.NotBefore, NotAfter: r.NotAfter,
			SHA256: r.Sha256Fp, KeyType: r.KeyType, Source: r.Source, HasKey: r.HasKey, CAID: r.CaID,
			RevokedAt: r.RevokedAt, CreatedAt: r.CreatedAt}
	}
	return out, nil
}

// Versions batch-loads version metadata by id, keyed by id. Callers
// rendering many certificates at once (for example a list page) use this
// instead of one Get per certificate.
func (s *Store) Versions(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]Version, error) {
	out := map[uuid.UUID]Version{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.q.ListCertificateVersionsByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = Version{ID: r.ID, CertID: r.CertID, Serial: r.Serial, NotBefore: r.NotBefore, NotAfter: r.NotAfter,
			SHA256: r.Sha256Fp, KeyType: r.KeyType, Source: r.Source, HasKey: r.HasKey, CAID: r.CaID,
			RevokedAt: r.RevokedAt, CreatedAt: r.CreatedAt}
	}
	return out, nil
}

func (s *Store) row(ctx context.Context, certID, versionID uuid.UUID) (sqlcgen.CertificateVersion, error) {
	r, err := s.q.GetCertificateVersion(ctx, sqlcgen.GetCertificateVersionParams{ID: versionID, CertID: certID})
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// Get returns one version's metadata.
func (s *Store) Get(ctx context.Context, certID, versionID uuid.UUID) (Version, error) {
	r, err := s.q.GetCertificateVersionMeta(ctx, sqlcgen.GetCertificateVersionMetaParams{ID: versionID, CertID: certID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, err
	}
	return Version{ID: r.ID, CertID: r.CertID, Serial: r.Serial, NotBefore: r.NotBefore, NotAfter: r.NotAfter,
		SHA256: r.Sha256Fp, KeyType: r.KeyType, Source: r.Source, HasKey: r.HasKey, CAID: r.CaID,
		RevokedAt: r.RevokedAt, CreatedAt: r.CreatedAt}, nil
}

// Material returns render input; the key is decrypted only when withKey and
// one is actually stored. A keyless version (r.PrivateKey nil) leaves
// PrivateKeyPKCS8 nil with no error even when withKey is set; render.Render
// only raises render.ErrNoKey once a key-bearing part is actually requested.
func (s *Store) Material(ctx context.Context, certID, versionID uuid.UUID, withKey bool) (render.Material, error) {
	if !withKey {
		// No key wanted: skip selecting the sealed key at all.
		d, err := s.q.GetCertificateVersionDER(ctx, sqlcgen.GetCertificateVersionDERParams{ID: versionID, CertID: certID})
		if errors.Is(err, pgx.ErrNoRows) {
			return render.Material{}, ErrNotFound
		}
		if err != nil {
			return render.Material{}, err
		}
		return render.Material{LeafDER: d.LeafDer, ChainDER: d.ChainDer}, nil
	}
	r, err := s.row(ctx, certID, versionID)
	if err != nil {
		return render.Material{}, err
	}
	m := render.Material{LeafDER: r.LeafDer, ChainDER: r.ChainDer}
	if withKey && r.PrivateKey != nil {
		if m.PrivateKeyPKCS8, err = s.box.Open(ctx, r.PrivateKey); err != nil {
			return render.Material{}, err
		}
	}
	return m, nil
}

// PrivateKey returns the decrypted PKCS#8 key and its key type (reuseKey).
// render.ErrNoKey when the version has no stored key.
func (s *Store) PrivateKey(ctx context.Context, certID, versionID uuid.UUID) ([]byte, string, error) {
	r, err := s.row(ctx, certID, versionID)
	if err != nil {
		return nil, "", err
	}
	if r.PrivateKey == nil {
		return nil, "", render.ErrNoKey
	}
	k, err := s.box.Open(ctx, r.PrivateKey)
	return k, r.KeyType, err
}
