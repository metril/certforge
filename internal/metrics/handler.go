package metrics

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/metril/certforge/internal/settings"
)

// promHandler serves Registry; built once since promhttp.HandlerFor is safe
// for concurrent use and every request reuses it.
var promHandler = promhttp.HandlerFor(Registry, promhttp.HandlerOpts{})

// errSectionNotRegistered means RegisterSettings was never called for this
// process (a wiring bug, not a runtime condition): loadSettings/Handler
// treat it the same as "disabled" (404) rather than panicking.
var errSectionNotRegistered = errors.New("metrics: prometheus settings section not registered")

// Handler serves GET /metrics (Shared contract, Metrics row): 404 while the
// "prometheus" section is disabled, else a constant-time bearer-token check
// against the section's stored token before promhttp.HandlerFor(Registry,
// ...) runs. store and sections are only used to build load (below); load
// itself is what ServeHTTP actually calls, so a unit test can substitute a
// fake without a database (same convention as authn.SettingsSource.load).
func Handler(store *settings.Store, sections *settings.Registry) http.Handler {
	return &handler{load: func(ctx context.Context) (Settings, error) { return loadSettings(ctx, store, sections) }}
}

type handler struct {
	load func(ctx context.Context) (Settings, error)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st, err := h.load(r.Context())
	if err != nil || !st.Enabled {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	token := bearerToken(r)
	if st.BearerToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(st.BearerToken)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	promHandler.ServeHTTP(w, r)
}

// bearerToken extracts the token from "Authorization: Bearer <token>", ""
// for a missing or differently-shaped header.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, prefix) {
		return ""
	}
	return strings.TrimPrefix(v, prefix)
}

// loadSettings reads the "prometheus" section fresh for every request
// (enabled and the token can change without a restart): the plain value
// (enabled) comes straight from the settings table; the token itself is a
// secret property, decrypted via Store.SectionSecrets, which is why
// sections is needed alongside store — to look up the registered Section
// that SectionSecrets takes.
func loadSettings(ctx context.Context, store *settings.Store, sections *settings.Registry) (Settings, error) {
	sec, ok := sections.Section(SectionName)
	if !ok {
		return Settings{}, errSectionNotRegistered
	}
	val, _, err := store.GetSection(ctx, sec)
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	if err := json.Unmarshal(val, &s); err != nil {
		return Settings{}, err
	}
	if !s.Enabled {
		return s, nil
	}
	secrets, err := store.SectionSecrets(ctx, sec)
	if err != nil {
		return Settings{}, err
	}
	s.BearerToken = secrets["bearerToken"]
	return s, nil
}
