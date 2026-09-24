package authn

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestDummyHashBuildsUnderSaturatedSemaphore must run before any other test
// in this package observes dummyHash/EqualizeTiming: dummyHash is cached
// with sync.OnceValue, so if its first-ever build hashed through the
// argon2 semaphore and got ErrBusy, EqualizeTiming would be silently and
// permanently disabled for the rest of the process. dummyHash must build
// without acquiring a slot so a saturated first call cannot do that.
func TestDummyHashBuildsUnderSaturatedSemaphore(t *testing.T) {
	restore := SetArgonConcurrency(1)
	defer restore()
	release, ok := TryAcquireArgonSlot()
	if !ok {
		t.Fatal("could not acquire the only slot")
	}
	h := dummyHash()
	release()
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("dummyHash built under a saturated semaphore = %q", h)
	}
	// Verified with the slot free: VerifyPassword itself still goes
	// through the semaphore (that part is correct and unchanged), only
	// building the dummy hash must not.
	if ok, err := VerifyPassword(h, "certforge-timing-equalizer"); err != nil || !ok {
		t.Fatalf("dummyHash does not verify: ok=%v err=%v", ok, err)
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
