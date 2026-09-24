//go:build e2e

// Package e2e holds compose-driven end-to-end tests. Run them with make e2e.
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func baseURL() string {
	if v := os.Getenv("CF_E2E_BASE_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8080"
}

func get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL()+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

func TestHealth(t *testing.T) {
	for _, p := range []string{"/healthz", "/readyz"} {
		if code, body := get(t, p); code != http.StatusOK {
			t.Fatalf("%s: %d %s", p, code, body)
		}
	}
}

func TestSetupStatusAndSpec(t *testing.T) {
	code, body := get(t, "/api/v1/setup/status")
	var st map[string]any
	if code != http.StatusOK || json.Unmarshal(body, &st) != nil {
		t.Fatalf("status %d %s", code, body)
	}
	if _, ok := st["needsSetup"]; !ok {
		t.Fatalf("body %s", body)
	}
	if code, _ := get(t, "/api/v1/openapi.json"); code != http.StatusOK {
		t.Fatalf("openapi %d", code)
	}
}
