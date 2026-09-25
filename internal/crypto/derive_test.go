package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// TestHKDFSHA256KnownAnswer checks the HKDF-SHA256 primitive DeriveKey is
// built on against RFC 5869's test case 1 (Appendix A.1), independent of
// CertForge's own key separation.
func TestHKDFSHA256KnownAnswer(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	want, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	got := make([]byte, 42)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, info), got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestDeriveKey(t *testing.T) {
	kek := bytes.Repeat([]byte{1}, 32)
	a, b := DeriveKey(kek, "certforge-audit"), DeriveKey(kek, "certforge-oidc-state")
	if len(a) != 32 || bytes.Equal(a, b) || bytes.Equal(a, kek) {
		t.Fatalf("keys not separated: %x %x", a, b)
	}
	if !bytes.Equal(a, DeriveKey(kek, "certforge-audit")) {
		t.Fatal("not deterministic")
	}
}
