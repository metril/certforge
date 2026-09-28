package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/metril/certforge/internal/config"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/kek"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/vault"
)

// buildKEK turns cfg.KEK into the active crypto.KeyWrapper and cfg.PreviousKEKs
// (Task 5: CF_KEK_PREVIOUS[_FILE], CF_KEK_PREVIOUS_VAULT_*) into previous
// ones, for crypto.NewEnvelope(active, previous...).
//
// legacy maps a candidate static KEK's crypto.KeyID to its raw bytes —
// active's own key if it is static, plus any previous KEK that is also
// static — the candidates EnsureRoot's legacy lookup checks against the
// canary's recorded KEKID on an existing install's first boot after
// upgrading to this phase, including the static→Transit upgrade where the
// original static KEK moves to CF_KEK_PREVIOUS and Transit becomes active
// (pre-flight ruling, TestEnsureRootTransitWithPreviousStatic). A
// Vault-Transit KEK, active or previous, never contributes to legacy: its
// raw key material never leaves Vault.
//
// For each Vault-Transit KEK (active or previous), buildKEK builds a
// vault.Client, logs it in and starts its renewal loop before returning —
// done here, before the caller constructs its settings.Store/Envelope, so
// an unreachable Vault fails boot fast with a redacted error instead of
// surfacing later as an opaque decrypt failure.
//
// closeFn stops every Vault client's renewal loop (a no-op for a static
// KEK) and must be deferred by the caller. On any error, closeFn has
// already been called for everything built so far — the caller need not
// call it again.
func buildKEK(ctx context.Context, cfg config.Config, log *slog.Logger) (active crypto.KeyWrapper, previous []crypto.KeyWrapper, legacy map[string][]byte, closeFn func(), err error) {
	legacy = map[string][]byte{}
	var closers []func()
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	active, err = buildOneKEK(ctx, cfg.KEK, log, "vault transit kek", legacy, &closers)
	if err != nil {
		closeAll()
		return nil, nil, nil, nil, err
	}
	for _, pc := range cfg.PreviousKEKs {
		w, err := buildOneKEK(ctx, pc, log, "vault transit kek (previous)", legacy, &closers)
		if err != nil {
			closeAll()
			return nil, nil, nil, nil, err
		}
		if w.ID() == active.ID() {
			closeAll()
			return nil, nil, nil, nil, errors.New("kek: CF_KEK_PREVIOUS* names the same key as the active KEK (CF_KEK/CF_KEK_VAULT_*)")
		}
		previous = append(previous, w)
	}
	return active, previous, legacy, closeAll, nil
}

// buildOneKEK builds a single KeyWrapper from kc: a static KeyWrapper over
// its bytes (also recorded in legacy), or a Vault Transit one (logged with
// logMsg, its Vault client's Close appended to *closers).
func buildOneKEK(ctx context.Context, kc config.KEKConfig, log *slog.Logger, logMsg string, legacy map[string][]byte, closers *[]func()) (crypto.KeyWrapper, error) {
	if kc.Kind == config.KEKKindVaultTransit {
		w, closeFn, err := buildTransitKEK(ctx, kc.Vault, log, logMsg)
		if err != nil {
			return nil, err
		}
		*closers = append(*closers, closeFn)
		return w, nil
	}
	key := kc.Key
	w := crypto.NewStaticWrapper(crypto.KeyID(key), key)
	legacy[w.ID()] = key
	return w, nil
}

func buildTransitKEK(ctx context.Context, vk *config.VaultKEK, log *slog.Logger, logMsg string) (crypto.KeyWrapper, func(), error) {
	vc, err := vault.New(vault.Config{
		Addr:      vk.Addr,
		Namespace: vk.Namespace,
		CAPEM:     vk.CAFile,
		Auth:      vaultKEKAuth(vk),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("vault kek: %w", err)
	}
	if err := vc.Login(ctx); err != nil {
		return nil, nil, fmt.Errorf("vault kek: login: %w", err)
	}
	// LookupSelf is the reachability check: TokenAuth's Login is a no-op,
	// so this is the first real request to Vault either way, and it also
	// seeds the lease info Start's renewal loop would otherwise fetch on
	// its own first tick.
	if _, err := vc.LookupSelf(ctx); err != nil {
		return nil, nil, fmt.Errorf("vault kek: %w", err)
	}
	vc.Start(ctx)
	log.Info(logMsg, "addr", vk.Addr, "mount", vk.Mount, "key", vk.Key)
	w := crypto.NewTransitWrapper(vaultTransitAPI{vc}, vk.Addr, vk.Mount, vk.Key)
	return w, vc.Close, nil
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

// kekInfo builds the kek.Service Info field from cfg and the KeyWrapper
// values buildKEK returned: only cfg (config.KEKConfig/VaultKEK) knows the
// configured kind and Vault address, and only the built wrappers know their
// ids (crypto.KeyID/TransitKEKID are never called again here).
func kekInfo(cfg config.Config, active crypto.KeyWrapper, previous []crypto.KeyWrapper) kek.Info {
	info := kek.Info{Kind: cfg.KEK.Kind, KEKID: active.ID()}
	if cfg.KEK.Kind == config.KEKKindVaultTransit && cfg.KEK.Vault != nil {
		info.VaultAddress = cfg.KEK.Vault.Addr
	}
	for i, pc := range cfg.PreviousKEKs {
		info.Previous = append(info.Previous, kek.Ref{Kind: pc.Kind, KEKID: previous[i].ID()})
	}
	return info
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
