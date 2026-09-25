package crypto

import (
	"bytes"
	"testing"
)

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
