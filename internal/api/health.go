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

// readyz checks the database and the KEK canary. Details are logged, not
// returned, because the endpoint is unauthenticated.
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
	status, word := http.StatusOK, "ready"
	if !ready {
		status, word = http.StatusServiceUnavailable, "unavailable"
	}
	writeJSON(w, status, map[string]any{"status": word, "checks": checks})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
