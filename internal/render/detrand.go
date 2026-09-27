package render

import (
	"crypto/sha256"
	"io"
	"math/rand/v2"
)

// DetRand returns a deterministic io.Reader keyed by the SHA-256 of the
// concatenated seeds, for reproducible PKCS12/JKS test fixtures. The same
// seed always yields the same byte stream; different seeds diverge.
func DetRand(seed ...[]byte) io.Reader {
	h := sha256.New()
	for _, s := range seed {
		h.Write(s)
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return rand.NewChaCha8(key)
}
