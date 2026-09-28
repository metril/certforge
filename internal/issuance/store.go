package issuance

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/vault"
)

// GlobalSettings reads settings keys; *settings.Store implements it.
type GlobalSettings interface {
	Get(ctx context.Context, key string, out any) error
}

// Store is the issuance data layer: CAs, accounts, DNS credentials,
// defaults, certificates, attempts and manual-dns records.
type Store struct {
	pool   *pgxpool.Pool
	q      *sqlcgen.Queries
	box    crypto.Box
	global GlobalSettings
	vault  *vault.Provider // set by SetVault; nil until wired (a vaultpki CA create/update then 422s)
}

// NewStore returns a Store. global may be nil (built-in defaults only).
func NewStore(pool *pgxpool.Pool, box crypto.Box, global GlobalSettings) *Store {
	return &Store{pool: pool, q: sqlcgen.New(pool), box: box, global: global}
}

func (s *Store) sealJSON(ctx context.Context, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return s.box.Seal(ctx, b)
}

func (s *Store) openJSON(ctx context.Context, sealed []byte, out any) error {
	b, err := s.box.Open(ctx, sealed)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// Begin starts a transaction on the store's pool (tests and certstore writes).
func (s *Store) Begin(ctx context.Context) (pgx.Tx, error) { return s.pool.Begin(ctx) }

// SetVault wires the Vault provider a vaultpki CA create reaches Vault's
// PKI secrets engine through (update only replaces mount/role/ttl and never
// contacts Vault). Left unset (nil), every vaultpki CA create 422s as
// unconfigured, same as an empty "vault" settings section would.
func (s *Store) SetVault(p *vault.Provider) { s.vault = p }
