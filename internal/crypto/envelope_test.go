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

// TestEnvelopeSelectsByKEKID covers the multi-wrapper Envelope (Task 5): a
// blob sealed under a previous KEK still decrypts once that KeyWrapper is
// passed to NewEnvelope, and Encrypt keeps using the active one.
func TestEnvelopeSelectsByKEKID(t *testing.T) {
	ctx := context.Background()
	activeKey, prevKey := testKey(1), testKey(2)
	active := NewStaticWrapper(KeyID(activeKey), activeKey)
	prev := NewStaticWrapper(KeyID(prevKey), prevKey)
	e := NewEnvelope(active, prev)

	if e.KEKID() != active.ID() {
		t.Fatalf("KEKID() = %q, want active %q", e.KEKID(), active.ID())
	}

	// A blob sealed under the previous KEK (before this envelope's active
	// KEK ever existed) still decrypts.
	oldBlob, err := NewEnvelope(prev).Encrypt(ctx, []byte("old secret"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Decrypt(ctx, oldBlob)
	if err != nil || string(got) != "old secret" {
		t.Fatalf("decrypt previous-KEK blob: got %q err %v", got, err)
	}

	// Encrypt always uses the active KEK.
	newBlob, err := e.Encrypt(ctx, []byte("new secret"))
	if err != nil {
		t.Fatal(err)
	}
	if newBlob.KEKID != active.ID() {
		t.Fatalf("new blob KEKID = %q, want active %q", newBlob.KEKID, active.ID())
	}

	ids := make([]string, 0, len(e.Wrappers()))
	for _, w := range e.Wrappers() {
		ids = append(ids, w.ID())
	}
	if len(ids) != 2 || ids[0] != active.ID() || ids[1] != prev.ID() {
		t.Fatalf("Wrappers() ids = %v", ids)
	}
}

// TestEnvelopeWrongKEKNamesIDs covers Decrypt's error for a blob sealed
// under a KEK this envelope has neither as active nor previous: the message
// names the blob's id and every configured id, and (Review Focus T1) never
// any wrapper's key bytes.
func TestEnvelopeWrongKEKNamesIDs(t *testing.T) {
	ctx := context.Background()
	unknownKey := testKey(3)
	blob, err := NewEnvelope(NewStaticWrapper(KeyID(unknownKey), unknownKey)).Encrypt(ctx, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	activeKey, prevKey := testKey(1), testKey(2)
	e := NewEnvelope(NewStaticWrapper(KeyID(activeKey), activeKey), NewStaticWrapper(KeyID(prevKey), prevKey))

	_, err = e.Decrypt(ctx, blob)
	if !errors.Is(err, ErrWrongKEK) {
		t.Fatalf("err = %v, want ErrWrongKEK", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, KeyID(unknownKey)) || !strings.Contains(msg, KeyID(activeKey)) || !strings.Contains(msg, KeyID(prevKey)) {
		t.Fatalf("error %q does not name every id", msg)
	}
	for _, k := range [][]byte{unknownKey, activeKey, prevKey} {
		if strings.Contains(msg, string(k)) {
			t.Fatalf("error %q leaks key bytes", msg)
		}
	}
}

func TestNewEnvelopeDuplicateIDPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	k := testKey(1)
	NewEnvelope(NewStaticWrapper("same", k), NewStaticWrapper("same", testKey(2)))
}

func TestNewStaticWrapperShortKeyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	NewStaticWrapper("x", []byte("short"))
}
