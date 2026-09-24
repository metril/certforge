package settings

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// CanaryKey holds a sealed known value that proves the KEK matches the DB.
const CanaryKey = "crypto.canary"

// ErrCanaryMismatch means the canary decrypted to an unexpected value.
var ErrCanaryMismatch = errors.New("settings: KEK canary plaintext mismatch")

// VerifyCanary decrypts the canary. It never writes.
func (s *Store) VerifyCanary(ctx context.Context) error {
	pt, err := s.GetSecret(ctx, CanaryKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(pt, crypto.CanaryPlaintext) {
		return ErrCanaryMismatch
	}
	return nil
}

// EnsureCanary writes the canary on first boot and verifies it afterwards.
// A canary sealed under another KEK is reported, never overwritten. The
// write is insert-if-absent (ON CONFLICT DO NOTHING), not an upsert: if two
// processes race to boot against a fresh database, only the first insert
// wins, and every caller re-verifies against whatever ended up stored
// instead of assuming its own write took effect.
func (s *Store) EnsureCanary(ctx context.Context) error {
	err := s.VerifyCanary(ctx)
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	b, err := s.env.Encrypt(ctx, crypto.CanaryPlaintext)
	if err != nil {
		return fmt.Errorf("settings: seal %s: %w", CanaryKey, err)
	}
	if _, err := s.q.InsertSettingSecretIfAbsent(ctx, sqlcgen.InsertSettingSecretIfAbsentParams{Key: CanaryKey, Secret: b.Marshal()}); err != nil {
		return fmt.Errorf("settings: seal %s: %w", CanaryKey, err)
	}
	return s.VerifyCanary(ctx)
}
