//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/metril/certforge/internal/api"
)

// TestServerInfo covers getServerInfo (Shared contract R7 Deviation): any
// authenticated principal (here, an API key) gets {version}; an anonymous
// caller is 401.
func TestServerInfo(t *testing.T) {
	e := newTestEnvOpts(t, func(d *api.Deps) { d.Version = "6a-test" })
	csrf, org := e.seedAdminSession()
	key := createKey(t, e, e.client, csrf, map[string]any{"name": "ci", "scopes": []string{"admin"}, "orgId": org}, http.StatusCreated)

	resp, body := e.doBearer(key.Token, http.MethodGet, "/api/v1/server-info", nil) //nolint:bodyclose // doClient closes the body
	var info struct {
		Version string `json:"version"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &info) != nil || info.Version != "6a-test" {
		t.Fatalf("server-info with key: %d %s", resp.StatusCode, body)
	}

	if resp, body := e.doClient(&http.Client{}, http.MethodGet, "/api/v1/server-info", nil, nil); resp.StatusCode != http.StatusUnauthorized { //nolint:bodyclose // doClient closes the body
		t.Fatalf("anonymous server-info: %d %s", resp.StatusCode, body)
	}
}
