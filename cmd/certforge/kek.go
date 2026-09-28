package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/metril/certforge/internal/config"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/vault"
)

// buildKEK turns cfg.KEK into an active crypto.KeyWrapper.
//
// For a static KEK this is immediate: a KeyWrapper over the 32 bytes
// already loaded, and legacy is that same key keyed by its own id — the
// candidate EnsureRoot needs to recognise an existing install's KEK on its
// first boot after upgrading to this phase.
//
// For a Vault-Transit KEK, buildKEK builds a vault.Client, logs it in and
// starts its renewal loop before returning — done here, before the caller
// constructs its settings.Store/Envelope, so an unreachable Vault fails
// boot fast with a redacted error instead of surfacing later as an opaque
// decrypt failure. legacy is empty: no static KEK bytes are ever held for a
// Transit-backed install (T5 adds CF_KEK_PREVIOUS* candidates to this map;
// none of those are Transit either, by construction of what "legacy" means
// here).
//
// closeFn stops the Vault client's renewal loop (a no-op for a static KEK)
// and must be deferred by the caller.
func buildKEK(ctx context.Context, cfg config.Config, log *slog.Logger) (active crypto.KeyWrapper, legacy map[string][]byte, closeFn func(), err error) {
	switch cfg.KEK.Kind {
	case config.KEKKindVaultTransit:
		return buildTransitKEK(ctx, cfg.KEK.Vault, log)
	default:
		key := cfg.KEK.Key
		w := crypto.NewStaticWrapper(crypto.KeyID(key), key)
		return w, map[string][]byte{crypto.KeyID(key): key}, func() {}, nil
	}
}

func buildTransitKEK(ctx context.Context, vk *config.VaultKEK, log *slog.Logger) (crypto.KeyWrapper, map[string][]byte, func(), error) {
	vc, err := vault.New(vault.Config{
		Addr:      vk.Addr,
		Namespace: vk.Namespace,
		CAPEM:     vk.CAFile,
		Auth:      vaultKEKAuth(vk),
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault kek: %w", err)
	}
	if err := vc.Login(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("vault kek: login: %w", err)
	}
	// LookupSelf is the reachability check: TokenAuth's Login is a no-op,
	// so this is the first real request to Vault either way, and it also
	// seeds the lease info Start's renewal loop would otherwise fetch on
	// its own first tick.
	if _, err := vc.LookupSelf(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("vault kek: %w", err)
	}
	vc.Start(ctx)
	log.Info("vault transit kek", "addr", vk.Addr, "mount", vk.Mount, "key", vk.Key)
	w := crypto.NewTransitWrapper(vaultTransitAPI{vc}, vk.Addr, vk.Mount, vk.Key)
	return w, map[string][]byte{}, vc.Close, nil
}

func vaultKEKAuth(vk *config.VaultKEK) vault.Auth {
	if vk.Token != "" {
		return vault.TokenAuth{Token: vk.Token}
	}
	return vault.AppRoleAuth{RoleID: vk.RoleID, SecretID: vk.SecretID}
}

// vaultTransitAPI adapts *vault.Client to crypto.TransitAPI. The two
// packages use separately-named (but field-identical) KeyInfo types —
// crypto.TransitAPI's doc comment explains why crypto cannot import
// internal/vault to share vault.KeyInfo directly — so this is where the
// values actually get converted.
type vaultTransitAPI struct{ c *vault.Client }

func (v vaultTransitAPI) TransitEncrypt(ctx context.Context, mount, key string, plaintext []byte) ([]byte, error) {
	return v.c.TransitEncrypt(ctx, mount, key, plaintext)
}

func (v vaultTransitAPI) TransitDecrypt(ctx context.Context, mount, key string, ciphertext []byte) ([]byte, error) {
	return v.c.TransitDecrypt(ctx, mount, key, ciphertext)
}

func (v vaultTransitAPI) TransitRewrap(ctx context.Context, mount, key string, ciphertext []byte) ([]byte, error) {
	return v.c.TransitRewrap(ctx, mount, key, ciphertext)
}

func (v vaultTransitAPI) TransitKeyInfo(ctx context.Context, mount, key string) (crypto.TransitKeyInfo, error) {
	info, err := v.c.TransitKeyInfo(ctx, mount, key)
	return crypto.TransitKeyInfo{LatestVersion: info.LatestVersion, MinDecryptionVersion: info.MinDecryptionVersion}, err
}

// rootKey ensures the sealed root secret exists and returns it. serve and
// bootstrap-admin both call this once, right after constructing their
// settings.Store and before EnsureCanary — the pre-flight ruling binding
// for this task: EnsureRoot must run first, so "canary absent" still means
// a genuinely fresh database. Callers must clear() the returned bytes once
// they are done deriving keys from it.
func rootKey(ctx context.Context, store *settings.Store, legacy map[string][]byte) ([]byte, error) {
	return store.EnsureRoot(ctx, legacy)
}
