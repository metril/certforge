//go:build integration

package settings_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/settings"
)

// fakeTransitAPI is a minimal, deterministic stand-in for a Transit backend,
// letting TestEnsureRootFreshTransit exercise EnsureRoot against a
// crypto.TransitWrapper without a real Vault. It never returns an error, so
// its behavior beyond satisfying crypto.TransitAPI is not exercised here.
type fakeTransitAPI struct{}

func (fakeTransitAPI) TransitEncrypt(_ context.Context, _, _ string, plaintext []byte) ([]byte, error) {
	out := append([]byte("vault:v1:"), plaintext...)
	return out, nil
}

func (fakeTransitAPI) TransitDecrypt(_ context.Context, _, _ string, ciphertext []byte) ([]byte, error) {
	return bytes.TrimPrefix(ciphertext, []byte("vault:v1:")), nil
}

func (fakeTransitAPI) TransitRewrap(_ context.Context, _, _ string, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func (fakeTransitAPI) TransitKeyInfo(context.Context, string, string) (crypto.TransitKeyInfo, error) {
	return crypto.TransitKeyInfo{LatestVersion: 1, MinDecryptionVersion: 1}, nil
}

// TestEnsureRootFresh covers a brand-new database booting on a static KEK:
// EnsureRoot seals 32 random bytes (nothing to match against yet) and every
// later call returns the same stored bytes.
func TestEnsureRootFresh(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	st := settings.NewStore(q, envelope(1))

	root, err := st.EnsureRoot(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 32 {
		t.Fatalf("root len = %d, want 32", len(root))
	}

	root2, err := st.EnsureRoot(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, root2) {
		t.Fatal("second EnsureRoot returned different bytes")
	}
}

// TestEnsureRootFreshTransit covers the same fresh-database case but on a
// Vault-Transit KEK: EnsureRoot must still seal a random root and must
// never return ErrNoLegacyRoot, since a fresh database has nothing to
// match a legacy static KEK against regardless of what backs the active
// KEK.
func TestEnsureRootFreshTransit(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	w := crypto.NewTransitWrapper(fakeTransitAPI{}, "https://vault.example.com:8200", "transit", "certforge-kek")
	st := settings.NewStore(q, crypto.NewEnvelope(w))

	root, err := st.EnsureRoot(ctx, map[string][]byte{})
	if err != nil {
		t.Fatalf("EnsureRoot on a fresh database with a Transit KEK: %v", err)
	}
	if len(root) != 32 {
		t.Fatalf("root len = %d, want 32", len(root))
	}
}

// TestEnsureRootNoLegacyFails covers an existing install (its canary is
// already sealed under a static KEK) with no root yet, now booting with no
// legacy candidate matching that KEK's id — the shape of "an existing
// install now configured with a Vault-Transit KEK and no static KEK at
// all". EnsureRoot must fail with ErrNoLegacyRoot rather than seed the root
// with anything else, which would silently change every derived key.
func TestEnsureRootNoLegacyFails(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	kek := bytes.Repeat([]byte{9}, 32)
	st := settings.NewStore(q, crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(kek), kek)))

	if err := st.EnsureCanary(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := st.EnsureRoot(ctx, map[string][]byte{}); !errors.Is(err, settings.ErrNoLegacyRoot) {
		t.Fatalf("err = %v, want ErrNoLegacyRoot", err)
	}
}

// TestEnsureRootTransitWithPreviousStatic covers the static→Transit upgrade
// (pre-flight ruling, Task 5): an existing install's canary is sealed under
// its original static KEK, and it now boots with that KEK moved to
// CF_KEK_PREVIOUS and a Vault-Transit KEK as CF_KEK. EnsureRoot's legacy
// lookup must still find the original KEK's bytes (by the canary's recorded
// KEKID) even though the *active* KEK is Transit and holds no bytes at all
// — legacy here only ever comes from a static candidate, previous or
// active, and rootSeed's env.Encrypt call always seals through the active
// (Transit) wrapper regardless of which legacy candidate matched.
func TestEnsureRootTransitWithPreviousStatic(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	oldKEK := bytes.Repeat([]byte{5}, 32)
	oldWrapper := crypto.NewStaticWrapper(crypto.KeyID(oldKEK), oldKEK)

	// Pre-upgrade: canary sealed under the original static KEK alone.
	preSt := settings.NewStore(q, crypto.NewEnvelope(oldWrapper))
	if err := preSt.EnsureCanary(ctx); err != nil {
		t.Fatal(err)
	}

	// Post-upgrade boot: active is Transit, oldWrapper is now previous.
	transit := crypto.NewTransitWrapper(fakeTransitAPI{}, "https://vault.example.com:8200", "transit", "certforge-kek")
	env := crypto.NewEnvelope(transit, oldWrapper)
	st := settings.NewStore(q, env)

	legacy := map[string][]byte{crypto.KeyID(oldKEK): oldKEK}
	root, err := st.EnsureRoot(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, oldKEK) {
		t.Fatal("root does not equal the previous static KEK's bytes")
	}

	// The canary (and anything else sealed pre-upgrade) still decrypts
	// through the previous wrapper the envelope was given.
	if err := st.VerifyCanary(ctx); err != nil {
		t.Fatalf("canary no longer verifies after the upgrade: %v", err)
	}
}

// TestEnsureRootExistingInstallKeepsAuditChain is the crucial safety net for
// the 5A upgrade (Review Focus T4): an install from before this phase wrote
// audit rows keyed with DeriveKey(kek.Key, "certforge-audit") directly. On
// its first boot after upgrading, EnsureRoot must seed the root with those
// exact KEK bytes (matched via the canary's recorded KEKID) so
// DeriveKey(root, "certforge-audit") reproduces the same key, and the
// existing chain still verifies — both immediately and after a new row is
// appended under the now-root-derived key.
func TestEnsureRootExistingInstallKeepsAuditChain(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	kek := bytes.Repeat([]byte{7}, 32)
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(kek), kek))
	st := settings.NewStore(q, env)

	// Simulate the pre-5A install: canary sealed, audit rows written and
	// keyed straight off the KEK.
	if err := st.EnsureCanary(ctx); err != nil {
		t.Fatal(err)
	}
	preUpgradeKey := crypto.DeriveKey(kek, "certforge-audit")
	aud := audit.New(pool, preUpgradeKey)
	if err := aud.Record(ctx, audit.Event{Action: "session.login", ResourceType: "session", ResourceID: "1", ActorType: "user", ActorID: "u1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := aud.Verify(ctx); err != nil {
		t.Fatalf("pre-upgrade verify: %v", err)
	}

	// The 5A boot: EnsureRoot must recover exactly the KEK's own bytes.
	legacy := map[string][]byte{crypto.KeyID(kek): kek}
	root, err := st.EnsureRoot(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, kek) {
		t.Fatal("root does not equal the legacy static KEK's bytes")
	}

	postUpgradeKey := crypto.DeriveKey(root, "certforge-audit")
	if !bytes.Equal(postUpgradeKey, preUpgradeKey) {
		t.Fatal("derived audit key changed across the upgrade")
	}

	aud2 := audit.New(pool, postUpgradeKey)
	if _, err := aud2.Verify(ctx); err != nil {
		t.Fatalf("post-upgrade verify of pre-existing rows: %v", err)
	}

	// Append under the root-derived key and verify the whole chain again.
	if err := aud2.Record(ctx, audit.Event{Action: "session.login", ResourceType: "session", ResourceID: "2", ActorType: "user", ActorID: "u1"}); err != nil {
		t.Fatal(err)
	}
	if n, err := aud2.Verify(ctx); err != nil || n != 2 {
		t.Fatalf("verify after append: n=%d err=%v", n, err)
	}
}
