package authn

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestBuildDummyHashUnderSaturatedSemaphore covers buildDummyHash directly
// (not the sync.OnceValue-cached dummyHash, which only ever runs its
// wrapped func once per process — a test calling the cached form would only
// prove anything if it happened to be the first-ever caller). If
// buildDummyHash hashed through the argon2 semaphore and got ErrBusy,
// dummyHash's cache would trap that failure and EqualizeTiming would be
// silently and permanently disabled for the rest of the process; this test
// exercises that path on every run, independent of test order.
func TestBuildDummyHashUnderSaturatedSemaphore(t *testing.T) {
	restore := SetArgonConcurrency(1)
	defer restore()
	release, ok := TryAcquireArgonSlot()
	if !ok {
		t.Fatal("could not acquire the only slot")
	}
	h := buildDummyHash()
	release()
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("buildDummyHash built under a saturated semaphore = %q", h)
	}
	// Verified with the slot free: VerifyPassword itself still goes
	// through the semaphore (that part is correct and unchanged), only
	// building the dummy hash must not.
	if ok, err := VerifyPassword(h, "certforge-timing-equalizer"); err != nil || !ok {
		t.Fatalf("buildDummyHash does not verify: ok=%v err=%v", ok, err)
	}
}

// TestAcquireArgonSlotReleasesOwnChannel covers a release closure that must
// drain the channel it actually acquired from, not read the package
// variable at release time: SetArgonConcurrency swaps that variable, and a
// release built as `func() { <-argonSlots }` would then block forever on
// the new (unrelated, empty) channel instead of freeing the old one.
func TestAcquireArgonSlotReleasesOwnChannel(t *testing.T) {
	restore := SetArgonConcurrency(1)
	defer restore()
	release, ok := TryAcquireArgonSlot()
	if !ok {
		t.Fatal("could not acquire the only slot")
	}
	restoreSwap := SetArgonConcurrency(2)
	defer restoreSwap()

	done := make(chan struct{})
	go func() {
		release()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("release blocked: it read the swapped package channel instead of the one it acquired")
	}
}

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("hash %q", h)
	}
	if ok, err := VerifyPassword(h, "correct horse battery"); err != nil || !ok {
		t.Fatalf("ok %v err %v", ok, err)
	}
	if ok, _ := VerifyPassword(h, "wrong horse battery"); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
}

func TestPasswordTooLong(t *testing.T) {
	long := strings.Repeat("a", MaxPasswordLength+1)
	if _, err := HashPassword(long); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("hash err = %v, want ErrPasswordTooLong", err)
	}
	h, err := HashPassword(strings.Repeat("a", MaxPasswordLength))
	if err != nil {
		t.Fatalf("hash at limit: %v", err)
	}
	if _, err := VerifyPassword(h, long); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("verify err = %v, want ErrPasswordTooLong", err)
	}
}

func TestArgonBusy(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	restore := SetArgonConcurrency(1)
	defer restore()
	release, ok := TryAcquireArgonSlot()
	if !ok {
		t.Fatal("could not acquire the only slot")
	}
	defer release()
	if _, err := HashPassword("correct horse battery"); !errors.Is(err, ErrBusy) {
		t.Fatalf("hash err = %v, want ErrBusy", err)
	}
	if _, err := VerifyPassword(h, "x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("verify err = %v, want ErrBusy", err)
	}
}

func TestVerifyMalformed(t *testing.T) {
	for _, enc := range []string{
		"",
		"plain",
		"$argon2i$v=19$m=1,t=1,p=1$AAAA$AAAA",
		"$argon2id$v=18$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2id$v=19$m=x$AAAA$AAAA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!$AAAA",
		"$argon2id$v=19$m=0,t=3,p=2$AAAA$AAAA",
	} {
		if _, err := VerifyPassword(enc, "pw"); err == nil {
			t.Fatalf("%q accepted", enc)
		}
	}
}

func TestVerifyPasswordCapsStoredParameters(t *testing.T) {
	for _, h := range []string{
		"$argon2id$v=19$m=4294967295,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=4000000,p=2$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=3,p=255$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if _, err := VerifyPassword(h, "whatever-password"); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("%s: err = %v, want ErrInvalidHash", h, err)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	cur := encodeArgon2id("pw", []byte("0123456789abcdef"))
	if NeedsRehash(cur) {
		t.Fatal("current-parameter hash flagged")
	}
	if !NeedsRehash(strings.Replace(cur, "m=65536,t=3", "m=19456,t=2", 1)) {
		t.Fatal("old-parameter hash not flagged")
	}
	if NeedsRehash("garbage") {
		t.Fatal("unparsable hash flagged")
	}
}
