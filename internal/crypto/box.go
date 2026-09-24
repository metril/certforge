package crypto

import "context"

// Box seals small secrets into bytea column values. EnvelopeBox (below)
// stores a marshalled envelope Blob; tests use cryptotest.PrefixBox.
type Box interface {
	Seal(ctx context.Context, plaintext []byte) ([]byte, error)
	Open(ctx context.Context, sealed []byte) ([]byte, error)
}

// EnvelopeBox stores values as marshalled envelope Blobs (per-row DEK,
// AES-256-GCM, wrapped by the active KEK).
type EnvelopeBox struct{ Env *Envelope }

func (b EnvelopeBox) Seal(ctx context.Context, plaintext []byte) ([]byte, error) {
	blob, err := b.Env.Encrypt(ctx, plaintext)
	if err != nil {
		return nil, err
	}
	return blob.Marshal(), nil
}

func (b EnvelopeBox) Open(ctx context.Context, sealed []byte) ([]byte, error) {
	var blob Blob
	if err := blob.Unmarshal(sealed); err != nil {
		return nil, err
	}
	return b.Env.Decrypt(ctx, blob)
}
