package render

import (
	"bytes"
	"io"
	"testing"
)

// TestDetRandSeedFramingAvoidsCollision: seeds must be framed (length
// prefixed) before hashing, or ("ab","c") and ("a","bc") hash to the same
// SHA-256 input and produce identical streams despite different seeds.
func TestDetRandSeedFramingAvoidsCollision(t *testing.T) {
	a := readN(t, DetRand([]byte("ab"), []byte("c")), 32)
	b := readN(t, DetRand([]byte("a"), []byte("bc")), 32)
	if bytes.Equal(a, b) {
		t.Fatal("differently split seeds produced identical streams")
	}
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	return buf
}
