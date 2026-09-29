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

// readyz checks the database, the KEK canary and, when configured, Vault
// reachability. Details are logged, not returned, because the endpoint is
// unauthenticated.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	checks := map[string]string{"database": "ok", "kek": "ok"}
	ready := true
	if err := s.d.Pool.Ping(ctx); err != nil {
		s.d.Log.Warn("readyz: database ping failed", "err", err)
		checks["database"], checks["kek"] = "failed", "unknown"
		ready = false
	} else if err := s.d.Settings.VerifyCanary(ctx); err != nil {
		s.d.Log.Warn("readyz: KEK canary failed", "err", err)
		checks["kek"] = "failed"
		ready = false
	}
	if word, present := s.vaultCheck(ctx); present {
		checks["vault"] = word
		if word == "failed" {
			ready = false
		}
	}
	status, word := http.StatusOK, "ready"
	if !ready {
		status, word = http.StatusServiceUnavailable, "unavailable"
	}
	writeJSON(w, status, map[string]any{"status": word, "checks": checks})
}

// vaultCheck reports /readyz's "vault" check (Shared contract): present
// only when Deps.KEKHealth is set (the KEK is Transit) or Deps.Vault has an
// address configured (the Integrations section). The underlying sys/health
// probe is cached for vaultCacheTTL; only its own error is cached, never
// the address or token that reached it, so nothing beyond the word below
// ever reaches the response body or this cache.
//
// A KEK-Transit failure is "failed": the server cannot decrypt without it.
// An Integrations-section failure is "degraded": Vault there only backs
// vaultpki/vault-kv, which fail their own way without it, so the rest of
// the server stays usable.
func (s *Server) vaultCheck(ctx context.Context) (word string, present bool) {
	transit := s.d.KEKHealth != nil
	if !transit && (s.d.Vault == nil || !s.d.Vault.Configured(ctx)) {
		return "", false
	}

	s.vaultMu.Lock()
	defer s.vaultMu.Unlock()
	if time.Since(s.vaultAt) >= vaultCacheTTL {
		var err error
		if transit {
			err = s.d.KEKHealth(ctx)
		} else if c, cerr := s.d.Vault.Client(ctx); cerr != nil {
			err = cerr
		} else {
			_, err = c.Health(ctx)
		}
		s.vaultAt, s.vaultErr = time.Now(), err
		if err != nil {
			s.d.Log.Warn("readyz: vault health check failed", "err", err)
		}
	}
	if s.vaultErr != nil {
		if transit {
			return "failed", true
		}
		return "degraded", true
	}
	return "ok", true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
