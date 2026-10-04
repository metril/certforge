package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// vaultCacheTTL is how long /readyz's "vault" check caches its sys/health
// probe (Shared contract).
const vaultCacheTTL = 30 * time.Second

// readyCacheTTL and readyFailCacheTTL are how long /readyz caches its
// database ping and KEK canary (the canary is one Vault transit decrypt
// under a Transit KEK, and the endpoint is unauthenticated). A failing
// result is cached for less, so recovery shows up quickly.
const (
	readyCacheTTL     = 5 * time.Second
	readyFailCacheTTL = time.Second
)

// readyChecks returns the cached database ping and KEK canary results,
// probing again once the cached ones are older than their TTL. The canary
// only runs when the ping succeeds.
func (s *Server) readyChecks(ctx context.Context) (dbErr, kekErr error) {
	s.readyMu.Lock()
	defer s.readyMu.Unlock()
	ttl := readyCacheTTL
	if s.readyDB != nil || s.readyKEK != nil {
		ttl = readyFailCacheTTL
	}
	if !s.readyAt.IsZero() && time.Since(s.readyAt) < ttl {
		return s.readyDB, s.readyKEK
	}
	s.readyDB, s.readyKEK = s.d.Pool.Ping(ctx), nil
	if s.readyDB != nil {
		s.d.Log.Warn("readyz: database ping failed", "err", s.readyDB)
	} else if s.readyKEK = s.d.Settings.VerifyCanary(ctx); s.readyKEK != nil {
		s.d.Log.Warn("readyz: KEK canary failed", "err", s.readyKEK)
	}
	s.readyAt = time.Now()
	return s.readyDB, s.readyKEK
}

// readyz checks the database, the KEK canary and, when configured, Vault
// reachability. Details are logged, not returned, because the endpoint is
// unauthenticated.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	checks := map[string]string{"database": "ok", "kek": "ok"}
	ready := true
	if dbErr, kekErr := s.readyChecks(ctx); dbErr != nil {
		checks["database"], checks["kek"] = "failed", "unknown"
		ready = false
	} else if kekErr != nil {
		checks["kek"] = "failed"
		ready = false
	}
	if word, present := s.vaultCheck(ctx); present {
		checks["vault"] = word
		if word == "failed" {
			ready = false
		}
	}
	if word, present := s.backupCheck(ctx); present {
		checks["backup"] = word // never makes ready false (Shared contract)
	}
	status, word := http.StatusOK, "ready"
	if !ready {
		status, word = http.StatusServiceUnavailable, "unavailable"
	}
	writeJSON(w, status, map[string]any{"status": word, "checks": checks})
}

// vaultCheck reports /readyz's "vault" check (Shared contract): present
// only when Deps.KEKHealth is set (the KEK is Transit) or Deps.Vault has an
// address configured (the Integrations section). The two are separate
// Vault configurations that can point at different addresses, so both are
// probed (each cached independently, vaultCacheTTL) whenever configured,
// not just the KEK's own — a batch 6 review fix: a Transit KEK's healthy
// probe used to skip the Integrations section's probe entirely, so a
// broken section address could never surface. Only its own error is
// cached, never the address or token that reached it, so nothing beyond
// the word below ever reaches the response body or this cache.
//
// A KEK-Transit failure is "failed": the server cannot decrypt without it.
// An Integrations-section failure is "degraded": Vault there only backs
// vaultpki/vault-kv, which fail their own way without it, so the rest of
// the server stays usable. The KEK's own failure wins when both fail.
func (s *Server) vaultCheck(ctx context.Context) (word string, present bool) {
	transit := s.d.KEKHealth != nil
	sectionConfigured := s.d.Vault != nil && s.d.Vault.Configured(ctx)
	if !transit && !sectionConfigured {
		return "", false
	}
	if transit && s.probeKEKVault(ctx) != nil {
		return "failed", true
	}
	if sectionConfigured && s.probeSectionVault(ctx) != nil {
		return "degraded", true
	}
	return "ok", true
}

// probeKEKVault runs (and caches, vaultCacheTTL) Deps.KEKHealth, the
// Transit KEK's own reachability probe.
func (s *Server) probeKEKVault(ctx context.Context) error {
	s.vaultMu.Lock()
	defer s.vaultMu.Unlock()
	if time.Since(s.vaultAt) >= vaultCacheTTL {
		err := s.d.KEKHealth(ctx)
		s.vaultAt, s.vaultErr = time.Now(), err
		if err != nil {
			s.d.Log.Warn("readyz: KEK vault health check failed", "err", err)
		}
	}
	return s.vaultErr
}

// probeSectionVault runs (and caches, vaultCacheTTL) a sys/health probe
// against the "vault" Integrations section's own client.
func (s *Server) probeSectionVault(ctx context.Context) error {
	s.vaultSectionMu.Lock()
	defer s.vaultSectionMu.Unlock()
	if time.Since(s.vaultSectionAt) >= vaultCacheTTL {
		var err error
		if c, cerr := s.d.Vault.Client(ctx); cerr != nil {
			err = cerr
		} else {
			_, err = c.Health(ctx)
		}
		s.vaultSectionAt, s.vaultSectionErr = time.Now(), err
		if err != nil {
			s.d.Log.Warn("readyz: vault section health check failed", "err", err)
		}
	}
	return s.vaultSectionErr
}

// backupCheck reports /readyz's "backup" check (Shared contract): present
// only when the "backup" section's schedule is not off, "degraded" when
// there has been no successful backup (scheduled or on-demand) in the last
// 7 days, "ok" otherwise. It never makes the server unready — a stale or
// never-run backup is an operator problem, not a reason to fail health
// checks and start a restart loop. s.d.Backup is nil in deployments that
// have not wired one yet (none today; defensive).
func (s *Server) backupCheck(ctx context.Context) (word string, present bool) {
	if s.d.Backup == nil {
		return "", false
	}
	st, err := s.d.Backup.Status(ctx)
	if err != nil {
		s.d.Log.Warn("readyz: backup status failed", "err", err)
		return "", false
	}
	if st.Schedule == "off" {
		return "", false
	}
	if st.LastSuccessAt == nil || time.Since(*st.LastSuccessAt) > 7*24*time.Hour {
		return "degraded", true
	}
	return "ok", true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
