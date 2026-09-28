package crypto

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// fakeTransitAPI is an in-memory stand-in for *vault.Client's four Transit
// methods, letting TransitWrapper be tested without a real Vault (or even
// the internal/vault package, which this package must never import — see
// TransitAPI's doc comment).
type fakeTransitAPI struct {
	mu            sync.Mutex
	latestVersion int
	encryptCalls  int
	decryptCalls  int
	rewrapCalls   int
	keyInfoCalls  int
}

func (f *fakeTransitAPI) TransitEncrypt(_ context.Context, _, _ string, plaintext []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.encryptCalls++
	return []byte(fmt.Sprintf("vault:v%d:%s", f.latestVersion, plaintext)), nil
}

func (f *fakeTransitAPI) TransitDecrypt(_ context.Context, _, _ string, ciphertext []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decryptCalls++
	var version int
	var pt string
	if _, err := fmt.Sscanf(string(ciphertext), "vault:v%d:%s", &version, &pt); err != nil {
		return nil, err
	}
	return []byte(pt), nil
}

func (f *fakeTransitAPI) TransitRewrap(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rewrapCalls++
	return []byte(fmt.Sprintf("vault:v%d:rewrapped", f.latestVersion)), nil
}

func (f *fakeTransitAPI) TransitKeyInfo(_ context.Context, _, _ string) (TransitKeyInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keyInfoCalls++
	return TransitKeyInfo{LatestVersion: f.latestVersion, MinDecryptionVersion: 1}, nil
}

func TestTransitWrapperID(t *testing.T) {
	api := &fakeTransitAPI{latestVersion: 1}
	w := NewTransitWrapper(api, "https://vault.example.com:8200", "transit", "certforge-kek")

	// Stable across key versions: bumping the key's version in Vault must
	// not change the wrapper's id (it identifies the key, not a version of
	// it).
	id1 := w.ID()
	api.latestVersion = 5
	if w.ID() != id1 {
		t.Fatalf("id changed with key version: %q vs %q", id1, w.ID())
	}

	// Trailing slash on the address is normalised away.
	w2 := NewTransitWrapper(api, "https://vault.example.com:8200/", "transit", "certforge-kek")
	if w2.ID() != id1 {
		t.Fatalf("trailing slash changed id: %q vs %q", id1, w2.ID())
	}

	// Changes with mount.
	if w3 := NewTransitWrapper(api, "https://vault.example.com:8200", "other-mount", "certforge-kek"); w3.ID() == id1 {
		t.Fatal("id did not change with mount")
	}

	// Changes with key.
	if w4 := NewTransitWrapper(api, "https://vault.example.com:8200", "transit", "other-key"); w4.ID() == id1 {
		t.Fatal("id did not change with key")
	}

	// Matches TransitKEKID directly.
	if want := TransitKEKID("https://vault.example.com:8200", "transit", "certforge-kek"); id1 != want {
		t.Fatalf("id %q != TransitKEKID %q", id1, want)
	}
	if id1[:6] != "vault-" {
		t.Fatalf("id %q missing vault- prefix", id1)
	}
}

func TestTransitWrapperWrapUnwrapRoundTrip(t *testing.T) {
	ctx := context.Background()
	api := &fakeTransitAPI{latestVersion: 1}
	w := NewTransitWrapper(api, "https://vault.example.com:8200", "transit", "certforge-kek")

	dek := []byte("thirty-two-byte-dek-material!!!")
	wrapped, err := w.Wrap(ctx, dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := w.Unwrap(ctx, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(dek) {
		t.Fatalf("got %q want %q", got, dek)
	}
}

func TestTransitRewrapOnlyOlderVersions(t *testing.T) {
	ctx := context.Background()
	api := &fakeTransitAPI{latestVersion: 1}
	w := NewTransitWrapper(api, "https://vault.example.com:8200", "transit", "certforge-kek")

	dek := []byte("thirty-two-byte-dek-material!!!")
	wrapped, err := w.Wrap(ctx, dek)
	if err != nil {
		t.Fatal(err)
	}

	// Same version as latest: no rewrap call, unchanged.
	rw, changed, err := w.Rewrap(ctx, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if changed || string(rw) != string(wrapped) {
		t.Fatalf("changed=%v rw=%q, want unchanged", changed, rw)
	}
	if api.rewrapCalls != 0 {
		t.Fatalf("rewrapCalls = %d, want 0", api.rewrapCalls)
	}
	if api.keyInfoCalls != 1 {
		t.Fatalf("keyInfoCalls = %d, want 1", api.keyInfoCalls)
	}

	// Vault rotates the key to v2: the v1 ciphertext is now older than
	// latest, so Rewrap must call TransitRewrap and report changed.
	api.mu.Lock()
	api.latestVersion = 2
	api.mu.Unlock()
	w.ResetKeyInfoCache()

	rw2, changed2, err := w.Rewrap(ctx, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !changed2 {
		t.Fatal("changed = false, want true for an older version")
	}
	if api.rewrapCalls != 1 {
		t.Fatalf("rewrapCalls = %d, want 1", api.rewrapCalls)
	}

	// Calling Rewrap again on the now-current ciphertext, without another
	// ResetKeyInfoCache, must not hit TransitKeyInfo again (cached per
	// job) and must not call TransitRewrap again.
	rw3, changed3, err := w.Rewrap(ctx, rw2)
	if err != nil {
		t.Fatal(err)
	}
	if changed3 {
		t.Fatalf("changed = true on an already-current ciphertext %q", rw3)
	}
	if api.rewrapCalls != 1 {
		t.Fatalf("rewrapCalls = %d, want still 1", api.rewrapCalls)
	}
	if api.keyInfoCalls != 2 {
		t.Fatalf("keyInfoCalls = %d, want 2 (one per ResetKeyInfoCache generation)", api.keyInfoCalls)
	}
}

// TestTransitWrapperImplementsRewrapper is a compile-time-ish check that
// TransitWrapper satisfies crypto.Rewrapper, which the multi-wrapper
// envelope (Task 5) needs to detect and rewrap Transit-backed blobs.
func TestTransitWrapperImplementsRewrapper(t *testing.T) {
	var _ Rewrapper = (*TransitWrapper)(nil)
	var _ KeyWrapper = (*TransitWrapper)(nil)
}
