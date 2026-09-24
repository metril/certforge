package crypto

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func newEnv(b byte) *Envelope {
	k := testKey(b)
	return NewEnvelope(NewStaticWrapper(KeyID(k), k))
}

func TestEnvelopeRoundTrip(t *testing.T) {
	ctx := context.Background()
	e := newEnv(1)
	blob, err := e.Encrypt(ctx, []byte("private key material"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed Blob
	if err := parsed.Unmarshal(blob.Marshal()); err != nil {
		t.Fatal(err)
	}
	if parsed.KEKID != e.KEKID() {
		t.Fatalf("kek id %q", parsed.KEKID)
	}
	got, err := e.Decrypt(ctx, parsed)
	if err != nil || string(got) != "private key material" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestEncryptIsRandomized(t *testing.T) {
	ctx := context.Background()
	e := newEnv(1)
	a, _ := e.Encrypt(ctx, []byte("same"))
	b, _ := e.Encrypt(ctx, []byte("same"))
	if bytes.Equal(a.Ciphertext, b.Ciphertext) || bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Fatal("ciphertexts or wrapped DEKs repeat")
	}
}

func TestDecryptWrongKEK(t *testing.T) {
	ctx := context.Background()
	blob, _ := newEnv(1).Encrypt(ctx, []byte("x"))
	if _, err := newEnv(2).Decrypt(ctx, blob); !errors.Is(err, ErrWrongKEK) {
		t.Fatalf("err = %v, want ErrWrongKEK", err)
	}
}

func TestDecryptSameIDDifferentKey(t *testing.T) {
	ctx := context.Background()
	e1 := NewEnvelope(NewStaticWrapper("same", testKey(1)))
	e2 := NewEnvelope(NewStaticWrapper("same", testKey(2)))
	blob, _ := e1.Encrypt(ctx, []byte("x"))
	if _, err := e2.Decrypt(ctx, blob); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestDecryptTampered(t *testing.T) {
	ctx := context.Background()
	e := newEnv(1)
	blob, _ := e.Encrypt(ctx, []byte("x"))
	blob.Ciphertext[len(blob.Ciphertext)-1] ^= 0xff
	if _, err := e.Decrypt(ctx, blob); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v", err)
	}
}

func TestDecryptBadNonceNoPanic(t *testing.T) {
	ctx := context.Background()
	e := newEnv(1)
	blob, _ := e.Encrypt(ctx, []byte("x"))
	blob.Nonce = blob.Nonce[:5]
	if _, err := e.Decrypt(ctx, blob); !errors.Is(err, ErrMalformedBlob) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnmarshalTruncatedNoPanic(t *testing.T) {
	ctx := context.Background()
	e := newEnv(1)
	blob, _ := e.Encrypt(ctx, []byte("some secret"))
	data := blob.Marshal()
	for i := 0; i < len(data); i++ {
		var b Blob
		if err := b.Unmarshal(data[:i]); err != nil {
			continue
		}
		if _, err := e.Decrypt(ctx, b); err == nil {
			t.Fatalf("truncated blob of %d bytes decrypted", i)
		}
	}
}

func TestKeyID(t *testing.T) {
	a, b := KeyID(testKey(1)), KeyID(testKey(2))
	if a != KeyID(testKey(1)) || a == b || !strings.HasPrefix(a, "static-") {
		t.Fatalf("ids %q %q", a, b)
	}
}

func TestNewStaticWrapperShortKeyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	NewStaticWrapper("x", []byte("short"))
}
