//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// schemaEntryOut mirrors gen.SchemaEntry's deploy-target-relevant fields.
type schemaEntryOut struct {
	Code      string `json:"code"`
	RunsOn    string `json:"runsOn"`
	KeyPolicy string `json:"keyPolicy"`
}

type metaSchemasOut struct {
	DeployTargets []schemaEntryOut `json:"deployTargets"`
}

type targetRegressionOut struct {
	ID            string   `json:"id"`
	RunsOn        string   `json:"runsOn"`
	StoredSecrets []string `json:"storedSecrets"`
}

// callStatus is apiClient.call's negative-path counterpart: it sends body
// (nil for none) as JSON with the session cookie/CSRF header and returns
// the raw status code and body instead of failing the test on a non-2xx
// response, for the 422/403 cases this test asserts on.
func (c *apiClient) callStatus(ctx context.Context, t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, baseURL()+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.hc.Do(req)
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

// bearerStatus is callStatus's counterpart for a bearer-token (API key)
// caller with no session cookie — the bearer path needs no CSRF header
// (internal/authn/middleware.go).
func bearerStatus(ctx context.Context, t *testing.T, token, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, baseURL()+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

// TestTargetsRegressionAgainstCompose (Task 8, R16) is the closing
// regression pass for Phase 7A's registry-driven deploy targets: it does
// not repeat TestVaultAgainstCompose's or TestAgentAgainstCompose's own
// full deploy flows (server-run vault-kv, agent-run traefik — both already
// run unchanged and green through the shared targets.Registry, elsewhere in
// this suite), only the registry-shape and gating assertions those two
// don't cover: GET /meta/schemas reports both shipped types' fixed
// runsOn/keyPolicy, a freshly created instance of each reads back with no
// stored secrets, runsOn mismatches are rejected everywhere the shared
// contract says so, and keys:export gates includeKey on create and update.
func TestTargetsRegressionAgainstCompose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	c := newAPIClient(t)
	orgID := c.authenticate(ctx, t)

	// (a) GET /meta/schemas: deployTargets reports the two shipped types'
	// fixed runsOn/keyPolicy (Shared contract, R16 amendment) — driven by
	// the registry (internal/targets.AddToMeta), not a per-type switch.
	var schemas metaSchemasOut
	c.call(ctx, t, http.MethodGet, "/api/v1/meta/schemas", nil, &schemas)
	want := map[string]schemaEntryOut{
		"traefik":  {RunsOn: "agent", KeyPolicy: "always"},
		"vault-kv": {RunsOn: "server", KeyPolicy: "optional"},
	}
	got := map[string]schemaEntryOut{}
	for _, e := range schemas.DeployTargets {
		got[e.Code] = e
	}
	for code, w := range want {
		g, ok := got[code]
		if !ok {
			t.Fatalf("deployTargets missing %q: %+v", code, schemas.DeployTargets)
		}
		if g.RunsOn != w.RunsOn || g.KeyPolicy != w.KeyPolicy {
			t.Fatalf("%s: runsOn=%q keyPolicy=%q, want %q/%q", code, g.RunsOn, g.KeyPolicy, w.RunsOn, w.KeyPolicy)
		}
	}

	// A fresh instance of each shipped type reads back with no stored
	// secrets — neither has a secret config field today, and
	// DeployTarget.storedSecrets must say so rather than omitting it.
	var traefikTarget, vaultTarget targetRegressionOut
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/deploy-targets", map[string]any{
		"name": "regression-traefik", "type": "traefik", "config": map[string]any{"dir": "/data/traefik-regression"},
	}, &traefikTarget)
	c.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/deploy-targets", map[string]any{
		"name": "regression-vault-kv", "type": "vault-kv", "config": map[string]any{},
	}, &vaultTarget)
	for _, want := range []struct{ id, runsOn string }{
		{traefikTarget.ID, "agent"}, {vaultTarget.ID, "server"},
	} {
		var got targetRegressionOut
		c.call(ctx, t, http.MethodGet, "/api/v1/orgs/"+orgID+"/deploy-targets/"+want.id, nil, &got)
		if got.RunsOn != want.runsOn {
			t.Fatalf("target %s: runsOn=%q, want %q", want.id, got.RunsOn, want.runsOn)
		}
		if len(got.StoredSecrets) != 0 {
			t.Fatalf("target %s: storedSecrets=%v, want none", want.id, got.StoredSecrets)
		}
	}

	// (b) runsOn mismatches are 422 everywhere the shared contract names:
	// forcing an agent-only type onto the server at create time, a
	// client-less grant onto an agent-run target, and changing runsOn on
	// update (type and runsOn are both immutable after create).
	if code, body := c.callStatus(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/deploy-targets", map[string]any{
		"name": "regression-traefik-forced-server", "type": "traefik", "runsOn": "server",
		"config": map[string]any{"dir": "/data/traefik-regression"},
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("create traefik runsOn=server: %d %s", code, body)
	}
	if code, body := c.callStatus(ctx, t, http.MethodPost, "/api/v1/orgs/"+orgID+"/deploy-targets/"+traefikTarget.ID+"/grants", map[string]any{
		"certificateId": "00000000-0000-0000-0000-000000000000",
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("client-less grant on agent-run target: %d %s", code, body)
	}
	if code, body := c.callStatus(ctx, t, http.MethodPatch, "/api/v1/orgs/"+orgID+"/deploy-targets/"+vaultTarget.ID, map[string]any{
		"name": "regression-vault-kv", "type": "vault-kv", "runsOn": "agent", "config": map[string]any{},
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("patch target runsOn: %d %s", code, body)
	}

	// (c) keys:export gates a server-run target's includeKey on both create
	// and update: an API key with delivery:write but not keys:export can
	// create a vault-kv target without includeKey, but not with it.
	var apiKey struct {
		Token string `json:"token"`
	}
	c.call(ctx, t, http.MethodPost, "/api/v1/api-keys", map[string]any{
		"name": "regression-delivery-write", "scopes": []string{"delivery:write"}, "orgId": orgID,
	}, &apiKey)

	if code, body := bearerStatus(ctx, t, apiKey.Token, http.MethodPost, "/api/v1/orgs/"+orgID+"/deploy-targets", map[string]any{
		"name": "regression-vault-kv-key", "type": "vault-kv", "config": map[string]any{"includeKey": true},
	}); code != http.StatusForbidden {
		t.Fatalf("create vault-kv includeKey without keys:export: %d %s", code, body)
	}
	var keyTarget targetRegressionOut
	code, body := bearerStatus(ctx, t, apiKey.Token, http.MethodPost, "/api/v1/orgs/"+orgID+"/deploy-targets", map[string]any{
		"name": "regression-vault-kv-key", "type": "vault-kv", "config": map[string]any{},
	})
	if code != http.StatusCreated {
		t.Fatalf("create vault-kv without includeKey: %d %s", code, body)
	}
	if err := json.Unmarshal(body, &keyTarget); err != nil {
		t.Fatalf("decode target: %v: %s", err, body)
	}
	if code, body := bearerStatus(ctx, t, apiKey.Token, http.MethodPatch, "/api/v1/orgs/"+orgID+"/deploy-targets/"+keyTarget.ID, map[string]any{
		"name": "regression-vault-kv-key", "type": "vault-kv", "config": map[string]any{"includeKey": true},
	}); code != http.StatusForbidden {
		t.Fatalf("update vault-kv includeKey without keys:export: %d %s", code, body)
	}
}
