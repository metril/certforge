package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
)

// TransitAPI is the subset of Vault (or OpenBao) Transit HTTP methods
// TransitWrapper needs to wrap, unwrap and rewrap a DEK. It is defined here,
// not imported from internal/vault, so this package never depends on it:
// internal/vault already imports internal/settings, which imports this
// package, so a crypto -> vault import would cycle. *vault.Client does not
// implement this interface directly (its TransitKeyInfo returns a
// differently-named struct); cmd/certforge adapts it.
type TransitAPI interface {
	TransitEncrypt(ctx context.Context, mount, key string, plaintext []byte) ([]byte, error)
	TransitDecrypt(ctx context.Context, mount, key string, ciphertext []byte) ([]byte, error)
	TransitRewrap(ctx context.Context, mount, key string, ciphertext []byte) ([]byte, error)
	TransitKeyInfo(ctx context.Context, mount, key string) (TransitKeyInfo, error)
}

// TransitKeyInfo mirrors vault.KeyInfo's fields (kept as a separate type for
// the reason TransitAPI's doc comment gives).
type TransitKeyInfo struct {
	LatestVersion        int
	MinDecryptionVersion int
}

// errBadTransitCiphertext means a stored blob is not shaped like Vault
// Transit's own "vault:vN:..." ciphertext.
var errBadTransitCiphertext = errors.New("crypto: malformed vault transit ciphertext")

// TransitWrapper is a KeyWrapper backed by Vault (or OpenBao) Transit: the
// DEK is wrapped and unwrapped through Vault's encrypt/decrypt operations,
// so the Transit key itself never leaves Vault.
type TransitWrapper struct {
	api        TransitAPI
	mount, key string
	id         string

	mu       sync.Mutex
	haveInfo bool
	info     TransitKeyInfo
}

// NewTransitWrapper returns a KeyWrapper that wraps and unwraps DEKs through
// Vault Transit at mount/key, reached over api.
func NewTransitWrapper(api TransitAPI, addr, mount, key string) *TransitWrapper {
	return &TransitWrapper{api: api, mount: mount, key: key, id: TransitKEKID(addr, mount, key)}
}

// TransitKEKID derives a stable, non-secret id for a Transit KEK from the
// Vault address, mount and key name it is reached at. Rotating the key's
// version inside Vault does not change this id; a different address, mount
// or key name does.
func TransitKEKID(addr, mount, key string) string {
	addr = strings.TrimRight(addr, "/")
	sum := sha256.Sum256([]byte("certforge-kek-id:vault:" + addr + "\x00" + mount + "\x00" + key))
	return "vault-" + hex.EncodeToString(sum[:])[:16]
}

// ID returns the Transit KEK's id.
func (w *TransitWrapper) ID() string { return w.id }

// Wrap encrypts dek under Vault Transit, returning Vault's opaque
// ciphertext ("vault:vN:...").
func (w *TransitWrapper) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	return w.api.TransitEncrypt(ctx, w.mount, w.key, dek)
}

// Unwrap decrypts a ciphertext produced by Wrap or already rewrapped by
// Rewrap.
func (w *TransitWrapper) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	return w.api.TransitDecrypt(ctx, w.mount, w.key, wrapped)
}

// Rewrap implements Rewrapper: it moves wrapped onto the Transit key's
// latest version without ever exposing the DEK, only when wrapped is not
// already there. The latest version is fetched once and cached until
// ResetKeyInfoCache is called (the rewrap job, Task 5, calls that once per
// run and then relies on the cache for the rest of it, instead of calling
// TransitKeyInfo once per stored blob).
func (w *TransitWrapper) Rewrap(ctx context.Context, wrapped []byte) ([]byte, bool, error) {
	version, err := transitCiphertextVersion(wrapped)
	if err != nil {
		return nil, false, err
	}
	info, err := w.keyInfo(ctx)
	if err != nil {
		return nil, false, err
	}
	if version >= info.LatestVersion {
		return wrapped, false, nil
	}
	rewrapped, err := w.api.TransitRewrap(ctx, w.mount, w.key, wrapped)
	if err != nil {
		return nil, false, err
	}
	return rewrapped, true, nil
}

// ResetKeyInfoCache clears the cached Transit key version, so the next
// Rewrap call fetches it fresh.
func (w *TransitWrapper) ResetKeyInfoCache() {
	w.mu.Lock()
	w.haveInfo = false
	w.mu.Unlock()
}

func (w *TransitWrapper) keyInfo(ctx context.Context) (TransitKeyInfo, error) {
	w.mu.Lock()
	if w.haveInfo {
		info := w.info
		w.mu.Unlock()
		return info, nil
	}
	w.mu.Unlock()

	info, err := w.api.TransitKeyInfo(ctx, w.mount, w.key)
	if err != nil {
		return TransitKeyInfo{}, err
	}
	w.mu.Lock()
	w.info, w.haveInfo = info, true
	w.mu.Unlock()
	return info, nil
}

// transitCiphertextVersion parses the version out of a Vault Transit
// ciphertext shaped "vault:vN:...".
func transitCiphertextVersion(wrapped []byte) (int, error) {
	parts := strings.SplitN(string(wrapped), ":", 3)
	if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") {
		return 0, errBadTransitCiphertext
	}
	n, err := strconv.Atoi(parts[1][1:])
	if err != nil {
		return 0, errBadTransitCiphertext
	}
	return n, nil
}
