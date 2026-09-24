package settings

import (
	"bytes"
	"context"
	"errors"

	"github.com/metril/certforge/internal/crypto"
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
// A canary sealed under another KEK is reported, never overwritten.
func (s *Store) EnsureCanary(ctx context.Context) error {
	err := s.VerifyCanary(ctx)
	if errors.Is(err, ErrNotFound) {
		return s.SetSecret(ctx, CanaryKey, crypto.CanaryPlaintext)
	}
	return err
}
