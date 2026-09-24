package authn

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// MinPasswordLength is the minimum local admin password length.
const MinPasswordLength = 12

// MaxPasswordLength caps password input accepted before hashing or
// verifying. Argon2's cost is proportional to input size only up to a
// point, but without a cap a client can still send an arbitrarily large
// body to force extra copying and hashing work; callers (the auth and
// setup HTTP handlers) reject an over-length password with 422 before
// calling Hash/VerifyPassword, and these functions guard the same limit
// for any caller that forgets to.
const MaxPasswordLength = 1024

// ErrInvalidHash means a stored password hash cannot be parsed.
var ErrInvalidHash = errors.New("authn: invalid password hash")

// ErrPasswordTooLong means the input exceeds MaxPasswordLength.
var ErrPasswordTooLong = errors.New("authn: password exceeds maximum length")

// ErrBusy means the argon2 concurrency limit was reached; callers should
// answer with 503 and a Retry-After header so the client backs off instead
// of every request paying full argon2 cost under load.
var ErrBusy = errors.New("authn: too many concurrent password operations, try again shortly")

const (
	argonMemory  uint32 = 64 * 1024
	argonTime    uint32 = 3
	argonThreads uint8  = 2
	argonKeyLen  uint32 = 32
)

var b64 = base64.RawStdEncoding

// argonSlots bounds how many argon2 hash/verify operations may run at once,
// so a burst of login or setup requests cannot exhaust server CPU. Capacity
// 4 is generous for a single local-admin auth path while still bounding
// worst-case concurrent cost.
var argonSlots = make(chan struct{}, 4)

// SetArgonConcurrency replaces the argon2 concurrency limit and returns a
// func that restores the previous one. Test-only.
func SetArgonConcurrency(n int) (restore func()) {
	prev := argonSlots
	argonSlots = make(chan struct{}, n)
	return func() { argonSlots = prev }
}

// TryAcquireArgonSlot reserves one argon2 slot without hashing anything, so
// tests can force ErrBusy from HashPassword/VerifyPassword. Release the
// slot with the returned func when done.
func TryAcquireArgonSlot() (release func(), ok bool) {
	return acquireArgonSlot()
}

func acquireArgonSlot() (release func(), ok bool) {
	ch := argonSlots
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, true
	default:
		return func() {}, false
	}
}

// encodeArgon2id hashes pw with salt under the package's fixed argon2id
// cost parameters and returns the PHC string. It does not touch the argon2
// concurrency semaphore; callers that need the limit enforced (HashPassword)
// acquire it themselves before calling this.
func encodeArgon2id(pw string, salt []byte) string {
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

// HashPassword returns an argon2id PHC string.
func HashPassword(pw string) (string, error) {
	if len(pw) > MaxPasswordLength {
		return "", ErrPasswordTooLong
	}
	release, ok := acquireArgonSlot()
	if !ok {
		return "", ErrBusy
	}
	defer release()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return encodeArgon2id(pw, salt), nil
}

// VerifyPassword checks pw against an argon2id PHC string in constant time.
func VerifyPassword(encoded, pw string) (bool, error) {
	if len(pw) > MaxPasswordLength {
		return false, ErrPasswordTooLong
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false, ErrInvalidHash
	}
	var m, t uint32
	var p uint8
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || n != 3 {
		return false, ErrInvalidHash
	}
	if m == 0 || t == 0 || p == 0 {
		// argon2.IDKey panics on zero parameters; a malformed hash in the
		// database must not crash the server.
		return false, ErrInvalidHash
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, ErrInvalidHash
	}
	release, ok := acquireArgonSlot()
	if !ok {
		return false, ErrBusy
	}
	defer release()
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// buildDummyHash computes the timing-equalizer hash via encodeArgon2id and
// deliberately does not go through HashPassword's argon2 concurrency
// semaphore: dummyHash caches this with sync.OnceValue, and if the first
// build hashed through the semaphore and got ErrBusy, EqualizeTiming would
// be silently and permanently disabled for the rest of the process. It is
// a plain func (not the sync.OnceValue itself) so tests can call it
// directly and observe each build, instead of only ever seeing whichever
// result got cached first.
func buildDummyHash() string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		// crypto/rand failure here is unrecoverable elsewhere in the
		// package too; fall back to a fixed salt so EqualizeTiming still
		// spends real argon2 time instead of caching an empty hash.
		salt = bytes.Repeat([]byte{0}, 16)
	}
	return encodeArgon2id("certforge-timing-equalizer", salt)
}

var dummyHash = sync.OnceValue(buildDummyHash)

// EqualizeTiming spends the same time as a real verification. Call it when
// no user exists so response time does not reveal that fact.
func EqualizeTiming(pw string) { _, _ = VerifyPassword(dummyHash(), pw) }
