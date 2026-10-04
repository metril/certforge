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

// WithTx returns a copy of the Store whose queries run in tx, for callers
// that read several things through one snapshot (the flow map). Methods that
// open their own transaction or use the pool directly are not affected.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	c := *s
	c.q = s.q.WithTx(tx)
	return &c
}

// sealJSON marshals v (typically a secret_cfg-shaped struct whose []byte
// fields hold private-key bytes, base64-encoded by encoding/json) and
// seals it. The marshalled plaintext is cleared once sealed — Security
// constraint: it must not outlive the call that needed it, same as the
// key bytes it was built from (clearSecretCfg and friends clear those
// separately, at their own call sites).
func (s *Store) sealJSON(ctx context.Context, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	return s.box.Seal(ctx, b)
}

// openJSON decrypts sealed and unmarshals it into out. The decrypted
// plaintext JSON (which, for a secret_cfg, still carries every key's
// base64 text) is cleared once unmarshalled: json.Unmarshal always copies
// into fresh []byte allocations for out's own []byte fields, so clearing b
// here never touches what out ends up holding.
func (s *Store) openJSON(ctx context.Context, sealed []byte, out any) error {
	b, err := s.box.Open(ctx, sealed)
	if err != nil {
		return err
	}
	defer clear(b)
	return json.Unmarshal(b, out)
}

// Begin starts a transaction on the store's pool (tests and certstore writes).
func (s *Store) Begin(ctx context.Context) (pgx.Tx, error) { return s.pool.Begin(ctx) }

// SetVault wires the Vault provider a vaultpki CA create reaches Vault's
// PKI secrets engine through (update only replaces mount/role/ttl and never
// contacts Vault). Left unset (nil), every vaultpki CA create 422s as
// unconfigured, same as an empty "vault" settings section would.
func (s *Store) SetVault(p *vault.Provider) { s.vault = p }
