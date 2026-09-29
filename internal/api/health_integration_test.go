//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/settings"
)

type readyBody struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

func readyz(t *testing.T, base string) (int, readyBody) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/readyz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b readyBody
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

func TestReadyz(t *testing.T) {
	e := newTestEnv(t)
	if code, b := readyz(t, e.srv.URL); code != http.StatusServiceUnavailable || b.Checks["kek"] != "failed" {
		t.Fatalf("before canary %d %+v", code, b)
	}
	if err := e.deps.Settings.EnsureCanary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, b := readyz(t, e.srv.URL); code != http.StatusOK || b.Status != "ready" || b.Checks["database"] != "ok" {
		t.Fatalf("ready %d %+v", code, b)
	}
}

func TestReadyzWrongKEK(t *testing.T) {
	e := newTestEnv(t)
	if err := e.deps.Settings.EnsureCanary(context.Background()); err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{9}, 32)
	d := e.deps
	d.Settings = settings.NewStore(d.Queries, crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(other), other)))
	srv := httptest.NewServer(api.NewRouter(d))
	defer srv.Close()
	code, b := readyz(t, srv.URL)
	if code != http.StatusServiceUnavailable || b.Status != "unavailable" || b.Checks["kek"] != "failed" || b.Checks["database"] != "ok" {
		t.Fatalf("wrong kek %d %+v", code, b)
	}
	// The server keeps serving: liveness stays green.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/healthz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz %d", resp.StatusCode)
	}
}

// TestReadyzVaultAbsentWhenUnconfigured covers the Shared contract: the
// "vault" check appears only when the "vault" settings section has an
// address or the KEK is Transit. Neither is true for a plain newTestEnv.
func TestReadyzVaultAbsentWhenUnconfigured(t *testing.T) {
	e := newTestEnv(t)
	if err := e.deps.Settings.EnsureCanary(context.Background()); err != nil {
		t.Fatal(err)
	}
	code, b := readyz(t, e.srv.URL)
	if code != http.StatusOK || b.Status != "ready" {
		t.Fatalf("ready %d %+v", code, b)
	}
	if _, ok := b.Checks["vault"]; ok {
		t.Fatalf("vault check present when unconfigured: %+v", b.Checks)
	}
}

// TestReadyzVaultDegradedForSection covers a configured but unreachable
// "vault" Integrations section (KEK not Transit): the server stays ready
// (200) and reports "degraded", not "failed" (Shared contract).
func TestReadyzVaultDegradedForSection(t *testing.T) {
	fv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.WriteHeader(http.StatusServiceUnavailable) // sealed
			_, _ = w.Write([]byte(`{"sealed":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer fv.Close()

	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	if err := e.deps.Settings.EnsureCanary(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, body := e.do(http.MethodPut, "/api/v1/settings/vault", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": fv.URL, "authMethod": "token", "token": "t1"}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seed vault settings: %d %s", resp.StatusCode, body)
	}

	code, b := readyz(t, e.srv.URL)
	if code != http.StatusOK || b.Status != "ready" || b.Checks["vault"] != "degraded" {
		t.Fatalf("degraded vault: %d %+v", code, b)
	}
}

// TestReadyzVaultFailedForTransitKEK covers a Transit KEK whose Vault
// health probe fails: the server reports not ready (503), unlike a section
// probe failure (Shared contract: "failed" only when the KEK is Transit).
func TestReadyzVaultFailedForTransitKEK(t *testing.T) {
	e := newTestEnvOpts(t, func(d *api.Deps) {
		d.KEKHealth = func(context.Context) error { return errors.New("vault sealed") }
	})
	if err := e.deps.Settings.EnsureCanary(context.Background()); err != nil {
		t.Fatal(err)
	}
	code, b := readyz(t, e.srv.URL)
	if code != http.StatusServiceUnavailable || b.Status != "unavailable" || b.Checks["vault"] != "failed" || b.Checks["kek"] != "ok" {
		t.Fatalf("failed transit kek: %d %+v", code, b)
	}
}

// TestReadyzVaultCached covers the Shared contract's 30 s cache on the
// sys/health probe: two /readyz calls back to back must not call KEKHealth
// twice.
func TestReadyzVaultCached(t *testing.T) {
	var calls atomic.Int64
	e := newTestEnvOpts(t, func(d *api.Deps) {
		d.KEKHealth = func(context.Context) error {
			calls.Add(1)
			return nil
		}
	})
	if err := e.deps.Settings.EnsureCanary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, b := readyz(t, e.srv.URL); code != http.StatusOK || b.Checks["vault"] != "ok" {
		t.Fatalf("first call: %d %+v", code, b)
	}
	if code, b := readyz(t, e.srv.URL); code != http.StatusOK || b.Checks["vault"] != "ok" {
		t.Fatalf("second call: %d %+v", code, b)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("KEKHealth called %d times, want 1 (cached)", got)
	}
}

// TestReadyzVaultNoSecrets covers the Shared contract and R10: no Vault
// address or token appears in the readiness body, only the check word.
func TestReadyzVaultNoSecrets(t *testing.T) {
	fv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer fv.Close()

	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	if err := e.deps.Settings.EnsureCanary(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, body := e.do(http.MethodPut, "/api/v1/settings/vault", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": fv.URL, "authMethod": "token", "token": "s3cret-tok"}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seed: %d %s", resp.StatusCode, body)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, e.srv.URL+"/readyz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	raw, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret-tok") || strings.Contains(string(raw), fv.URL) {
		t.Fatalf("readyz body leaks secret or address: %s", raw)
	}
	var b readyBody
	if err := json.Unmarshal(raw, &b); err != nil || b.Checks["vault"] != "degraded" {
		t.Fatalf("expected degraded: %s (err %v)", raw, err)
	}
}
