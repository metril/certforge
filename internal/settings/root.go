package settings

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// rootSize is the sealed root secret's length in bytes: the same size as
// every DEK and static KEK (crypto.KEKSize-equivalent), so it can stand in
// directly for a legacy static KEK's bytes.
const rootSize = 32

// RootKey holds a secret sealed under the active KEK. Every key this server
// derives (the audit chain's HMAC key, the OIDC state HMAC key, ...) is now
// HKDF'd from this root instead of straight from the KEK's own bytes, so
// rotating which KEK wraps it (Task 5) never changes the derived keys and
// never forks the audit chain.
const RootKey = "crypto.root"

// RewrapKey records a rewrap job's progress (Task 5).
const RewrapKey = "crypto.rewrap"

// ErrNoLegacyRoot means an existing install (its KEK canary is already
// sealed) has no root secret yet, and none of EnsureRoot's legacy
// candidates match the canary's recorded KEKID: there is no way to seed the
// root with the same bytes DeriveKey(kek.Key, ...) has been using all
// along, so seeding it with anything else would silently fork the audit
// chain (every previously derived key would change). This is expected the
// first time an existing install boots on a Vault-Transit KEK with no
// static KEK configured: configure the original static KEK as CF_KEK once,
// long enough for EnsureRoot to seed the root, then switch to Transit.
var ErrNoLegacyRoot = errors.New("settings: existing install: configure its original static KEK as CF_KEK or CF_KEK_PREVIOUS")

// EnsureRoot reads the sealed root secret, creating it on first boot.
//
// A fresh database (its KEK canary is not sealed yet) gets 32 random bytes:
// nothing has ever been derived from a KEK before, so there is nothing to
// match.
//
// An existing install (its canary is already sealed) instead needs the
// root to equal whatever DeriveKey(kek.Key, ...) calls have used all
// along, or every key derived from it — the audit HMAC key above all —
// would change and the audit chain would appear tampered. legacy maps a
// candidate static KEK's crypto.KeyID to its raw bytes; EnsureRoot uses the
// one whose id matches the canary's recorded KEKID. No match (for example
// an existing install now booting on a Vault-Transit KEK with no static
// KEK configured) fails with ErrNoLegacyRoot rather than silently forking
// the chain.
//
// The write is insert-if-absent and re-read, the same pattern EnsureCanary
// uses: several processes racing to boot against the same fresh database
// all end up returning the one root that won the insert.
//
// EnsureRoot must run before EnsureCanary in serve and bootstrap-admin, so
// "canary absent" here still means a genuinely fresh database.
func (s *Store) EnsureRoot(ctx context.Context, legacy map[string][]byte) ([]byte, error) {
	root, err := s.GetSecret(ctx, RootKey)
	if err == nil {
		return root, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	seed, err := s.rootSeed(ctx, legacy)
	if err != nil {
		return nil, err
	}
	b, err := s.env.Encrypt(ctx, seed)
	if err != nil {
		return nil, fmt.Errorf("settings: seal %s: %w", RootKey, err)
	}
	if _, err := s.q.InsertSettingSecretIfAbsent(ctx, sqlcgen.InsertSettingSecretIfAbsentParams{Key: RootKey, Secret: b.Marshal()}); err != nil {
		return nil, fmt.Errorf("settings: seal %s: %w", RootKey, err)
	}
	return s.GetSecret(ctx, RootKey)
}

// SealedRoot returns the raw crypto.root settings row: a marshalled
// crypto.Blob, still sealed. Backup's Write (internal/backup, Task 10)
// records this unchanged as Header.RootSealed, so Restore can later prove
// its configured KEK unseals the exact same bytes before writing anything,
// and can compare the freshly restored row against it byte for byte
// before committing.
func (s *Store) SealedRoot(ctx context.Context) ([]byte, error) {
	row, err := s.q.GetSetting(ctx, RootKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("settings: get %s: %w", RootKey, err)
	}
	if row.Secret == nil {
		return nil, ErrNotFound
	}
	return row.Secret, nil
}

// rootSeed picks the bytes to seal as the root on first creation.
func (s *Store) rootSeed(ctx context.Context, legacy map[string][]byte) ([]byte, error) {
	canaryKEKID, present, err := s.canaryKEKID(ctx)
	if err != nil {
		return nil, err
	}
	if !present {
		seed := make([]byte, rootSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		return seed, nil
	}
	if key, ok := legacy[canaryKEKID]; ok {
		return key, nil
	}
	return nil, ErrNoLegacyRoot
}

// canaryKEKID reports the KEKID the crypto.canary row was originally sealed
// under, without needing to decrypt it under the currently active KEK (the
// KEKID is the Blob's own plaintext header, not the encrypted payload). A
// row that does not exist, or exists with a NULL secret (treated as absent
// the same way EnsureCanary does), reports present=false.
func (s *Store) canaryKEKID(ctx context.Context) (id string, present bool, err error) {
	row, err := s.q.GetSetting(ctx, CanaryKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("settings: get %s: %w", CanaryKey, err)
	}
	if row.Secret == nil {
		return "", false, nil
	}
	var b crypto.Blob
	if err := b.Unmarshal(row.Secret); err != nil {
		return "", false, fmt.Errorf("settings: secret %s: %w", CanaryKey, err)
	}
	return b.KEKID, true, nil
}
