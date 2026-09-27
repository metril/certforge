package render

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/rand/v2"
)

// DetRand returns a deterministic io.Reader keyed by the SHA-256 of the
// given seeds, for reproducible PKCS12/JKS test fixtures. Each seed is
// hashed with its own 8-byte big-endian length prefix, so seed boundaries
// cannot collide: DetRand([]byte("ab"), []byte("c")) and
// DetRand([]byte("a"), []byte("bc")) diverge. The same seeds always yield
// the same byte stream; different seeds diverge.
//
// The seed must include secret material — the export/store password and
// the private key, not public identifiers alone — because the resulting
// stream drives PKCS12 and JKS salts and IVs directly: a seed guessable
// from public information makes those salts and IVs guessable too.
func DetRand(seed ...[]byte) io.Reader {
	h := sha256.New()
	for _, s := range seed {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write(s)
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return rand.NewChaCha8(key)
}
