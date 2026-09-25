package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey derives a 32-byte subkey from the KEK with HKDF-SHA256. info
// separates uses: "certforge-audit" (audit chain HMAC) and
// "certforge-oidc-state" (OIDC state cookie HMAC).
func DeriveKey(kek []byte, info string) []byte {
	k := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, kek, nil, []byte(info)), k); err != nil {
		panic(err) // HKDF-SHA256 yields up to 8160 bytes; 32 cannot fail
	}
	return k
}
