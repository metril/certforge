// Package crypto implements CertForge's envelope encryption. Every secret is
// sealed with a fresh AES-256-GCM data key (DEK), and the DEK is wrapped by a
// key-encryption key (KEK) behind the KeyWrapper interface.
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	// ErrWrongKEK means the blob was sealed under a different KEK id.
	ErrWrongKEK = errors.New("crypto: blob was sealed with a different KEK")
	// ErrDecrypt means authentication failed (wrong key or tampered data).
	ErrDecrypt = errors.New("crypto: authentication failed")
	// ErrMalformedBlob means the stored bytes are not a valid blob.
	ErrMalformedBlob = errors.New("crypto: malformed blob")
)

// CanaryPlaintext is sealed at startup and decrypted by /readyz to prove the
// configured KEK matches the database.
var CanaryPlaintext = []byte("certforge-kek-canary-v1")

// KeyWrapper wraps and unwraps data keys with a key-encryption key.
type KeyWrapper interface {
	ID() string
	Wrap(ctx context.Context, dek []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

// Rewrapper is implemented by a KeyWrapper that can move an already-wrapped
// DEK onto newer key material without ever exposing the DEK itself (Vault
// Transit's rewrap operation: TransitWrapper implements this). changed
// reports whether wrapped was actually re-encrypted; false with a nil error
// means it was already current and rewrapped is the same bytes as wrapped.
type Rewrapper interface {
	Rewrap(ctx context.Context, wrapped []byte) (rewrapped []byte, changed bool, err error)
}

// KeyID derives a stable, non-secret id for a static KEK.
func KeyID(key []byte) string {
	sum := sha256.Sum256(append([]byte("certforge-kek-id:"), key...))
	return "static-" + hex.EncodeToString(sum[:8])
}

type staticWrapper struct {
	id   string
	aead cipher.AEAD
}

// NewStaticWrapper returns an AES-256-GCM key wrapper for a 32-byte KEK.
// It panics on a wrong key length; config.Load guarantees 32 bytes.
func NewStaticWrapper(id string, key []byte) KeyWrapper {
	aead, err := newGCM(key)
	if err != nil {
		panic(fmt.Sprintf("crypto: NewStaticWrapper: %v", err))
	}
	return &staticWrapper{id: id, aead: aead}
}

func (w *staticWrapper) ID() string { return w.id }

func (w *staticWrapper) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	nonce := make([]byte, w.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return w.aead.Seal(nonce, nonce, dek, []byte("certforge-dek:"+w.id)), nil
}

func (w *staticWrapper) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	ns := w.aead.NonceSize()
	if len(wrapped) < ns+w.aead.Overhead() {
		return nil, ErrMalformedBlob
	}
	dek, err := w.aead.Open(nil, wrapped[:ns], wrapped[ns:], []byte("certforge-dek:"+w.id))
	if err != nil {
		return nil, ErrDecrypt
	}
	return dek, nil
}

// Envelope seals data with per-call DEKs wrapped by one KeyWrapper.
type Envelope struct {
	w KeyWrapper
}

// NewEnvelope returns an Envelope using w as the active KEK.
func NewEnvelope(w KeyWrapper) *Envelope { return &Envelope{w: w} }

// KEKID returns the active KEK id.
func (e *Envelope) KEKID() string { return e.w.ID() }

// Encrypt seals plaintext under a fresh DEK.
func (e *Envelope) Encrypt(ctx context.Context, plaintext []byte) (Blob, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return Blob{}, err
	}
	defer clear(dek)
	wrapped, err := e.w.Wrap(ctx, dek)
	if err != nil {
		return Blob{}, fmt.Errorf("crypto: wrap DEK: %w", err)
	}
	aead, err := newGCM(dek)
	if err != nil {
		return Blob{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Blob{}, err
	}
	id := e.w.ID()
	return Blob{KEKID: id, WrappedDEK: wrapped, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, []byte(id))}, nil
}

// Decrypt opens b. It never panics on malformed input.
func (e *Envelope) Decrypt(ctx context.Context, b Blob) ([]byte, error) {
	if b.KEKID != e.w.ID() {
		return nil, fmt.Errorf("%w: blob %q, active %q", ErrWrongKEK, b.KEKID, e.w.ID())
	}
	dek, err := e.w.Unwrap(ctx, b.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap DEK: %w", err)
	}
	defer clear(dek)
	aead, err := newGCM(dek)
	if err != nil {
		return nil, ErrMalformedBlob
	}
	if len(b.Nonce) != aead.NonceSize() {
		return nil, ErrMalformedBlob
	}
	pt, err := aead.Open(nil, b.Nonce, b.Ciphertext, []byte(b.KEKID))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
