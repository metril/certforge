package agentca

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	cfcrypto "github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// lockKey serializes CA creation and rotation (audit uses 0x43460002).
const lockKey int64 = 0x43460003

// Store errors.
var (
	ErrNoActive = errors.New("agentca: no active CA")
	ErrActive   = errors.New("agentca: the active CA cannot be retired")
	ErrNotFound = errors.New("agentca: no such CA")
)

// InUseError blocks retiring a CA that still anchors live agent certificates.
type InUseError struct{ N int64 }

func (e *InUseError) Error() string {
	return fmt.Sprintf("agentca: %d active agent certificates were issued by this CA", e.N)
}

// Info is a CA without its key, for listings.
type Info struct {
	ID                uuid.UUID
	Status            string
	Cert              *x509.Certificate
	ActiveClientCerts int64
	CreatedAt         time.Time
}

// Store keeps agent CAs with their keys sealed by box.
type Store struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
	box  cfcrypto.Box
	now  func() time.Time
}

// NewStore returns a Store over pool.
func NewStore(pool *pgxpool.Pool, box cfcrypto.Box) *Store {
	return &Store{pool: pool, q: sqlcgen.New(pool), box: box, now: time.Now}
}

func (s *Store) decode(ctx context.Context, row sqlcgen.AgentCa) (*CA, error) {
	cert, err := x509.ParseCertificate(row.CertDer)
	if err != nil {
		return nil, fmt.Errorf("agentca: parse CA %s: %w", row.ID, err)
	}
	pkcs8, err := s.box.Open(ctx, row.Key)
	if err != nil {
		return nil, fmt.Errorf("agentca: open CA key %s: %w", row.ID, err)
	}
	k, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("agentca: parse CA key %s: %w", row.ID, err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("agentca: CA key %s is %T, want ECDSA", row.ID, k)
	}
	return &CA{ID: row.ID, Status: row.Status, Cert: cert, Key: key, CreatedAt: row.CreatedAt}, nil
}

// WithQueries returns a Store reading through q (a transaction's queries),
// so a read inside an open transaction does not take a second pool connection.
func (s *Store) WithQueries(q *sqlcgen.Queries) *Store {
	c := *s
	c.q = q
	return &c
}

// Active returns the active CA, or ErrNoActive.
func (s *Store) Active(ctx context.Context) (*CA, error) {
	row, err := s.q.GetActiveAgentCA(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoActive
	}
	if err != nil {
		return nil, err
	}
	return s.decode(ctx, row)
}

// Oldest returns the oldest non-retired CA, which signs the listener
// certificate: every agent trusts it until it is retired. ErrNoActive when
// there is none.
func (s *Store) Oldest(ctx context.Context) (*CA, error) {
	row, err := s.q.GetOldestTrustedAgentCA(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoActive
	}
	if err != nil {
		return nil, err
	}
	return s.decode(ctx, row)
}

// Get returns one CA with its key.
func (s *Store) Get(ctx context.Context, id uuid.UUID) (*CA, error) {
	row, err := s.q.GetAgentCA(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.decode(ctx, row)
}

func (s *Store) insert(ctx context.Context, q *sqlcgen.Queries) (sqlcgen.AgentCa, error) {
	cert, key, err := NewCA(s.now())
	if err != nil {
		return sqlcgen.AgentCa{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return sqlcgen.AgentCa{}, err
	}
	sealed, err := s.box.Seal(ctx, pkcs8)
	if err != nil {
		return sqlcgen.AgentCa{}, err
	}
	return q.InsertAgentCA(ctx, sqlcgen.InsertAgentCAParams{CertDer: cert.Raw, Key: sealed, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter})
}

// EnsureActive returns the active CA, creating the first one under an
// advisory lock so concurrent callers agree on a single CA.
func (s *Store) EnsureActive(ctx context.Context) (*CA, error) {
	if ca, err := s.Active(ctx); !errors.Is(err, ErrNoActive) {
		return ca, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return nil, err
	}
	q := s.q.WithTx(tx)
	row, err := q.GetActiveAgentCA(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		row, err = s.insert(ctx, q)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.decode(ctx, row)
}

// Rotate creates a new active CA and marks the previous one retiring.
// Previous is the CA that was active before this call, nil if none was
// (read in the same transaction, so a concurrent Rotate never races it).
func (s *Store) Rotate(ctx context.Context) (ca *CA, previous *uuid.UUID, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return nil, nil, err
	}
	q := s.q.WithTx(tx)
	retired, err := q.MarkActiveAgentCARetiring(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(retired) > 0 {
		previous = &retired[0]
	}
	row, err := s.insert(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	ca, err = s.decode(ctx, row)
	return ca, previous, err
}

// Retire stops trusting a CA that is not active and anchors no live agent
// certificate. Retiring a retired CA is a no-op.
func (s *Store) Retire(ctx context.Context, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return err
	}
	q := s.q.WithTx(tx)
	row, err := q.LockAgentCA(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	switch row.Status {
	case "active":
		return ErrActive
	case "retired":
		return nil
	}
	n, err := q.CountActiveClientCertsForCA(ctx, id)
	if err != nil {
		return err
	}
	if n > 0 {
		return &InUseError{N: n}
	}
	if _, err := q.SetAgentCARetired(ctx, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Trusted returns every non-retired CA certificate, oldest first.
func (s *Store) Trusted(ctx context.Context) ([]*x509.Certificate, error) {
	rows, err := s.q.ListTrustedAgentCAs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*x509.Certificate, 0, len(rows))
	for _, r := range rows {
		c, err := x509.ParseCertificate(r.CertDer)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// List returns every CA, newest first, with its live agent certificate count.
func (s *Store) List(ctx context.Context) ([]Info, error) {
	rows, err := s.q.ListAgentCAs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(rows))
	for _, r := range rows {
		c, err := x509.ParseCertificate(r.CertDer)
		if err != nil {
			return nil, err
		}
		out = append(out, Info{ID: r.ID, Status: r.Status, Cert: c, ActiveClientCerts: r.ActiveClientCerts, CreatedAt: r.CreatedAt})
	}
	return out, nil
}
