//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
