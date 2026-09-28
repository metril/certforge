//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/vault"
)

// TestVaultPutRequiresTokenOnAddressChange covers the re-entry rule on
// PUT /settings/vault (pre-flight ruling, TestVaultPutRequiresTokenOnAddressChange):
// an address/namespace change must re-send token/secretId for the active
// authMethod; omitted or "__unchanged__" is 422 "re-enter the token" once a
// value is already stored, but not on the section's first save.
func TestVaultPutRequiresTokenOnAddressChange(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()

	resp, body := e.do(http.MethodPut, "/api/v1/settings/vault", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": "https://vault.test:8200", "authMethod": "token"}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first save: %d %s", resp.StatusCode, body)
	}

	resp, body = e.do(http.MethodPut, "/api/v1/settings/vault", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": "https://vault.test:8200", "authMethod": "token"}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unchanged address, no token: %d %s", resp.StatusCode, body)
	}

	resp, body = e.do(http.MethodPut, "/api/v1/settings/vault", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": "https://other.test:8200", "authMethod": "token"}, csrf)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body), "re-enter the token") {
		t.Fatalf("changed address, omitted token: %d %s", resp.StatusCode, body)
	}

	resp, body = e.do(http.MethodPut, "/api/v1/settings/vault", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": "https://other.test:8200", "authMethod": "token", "token": "__unchanged__"}, csrf)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body), "re-enter the token") {
		t.Fatalf("changed address, __unchanged__ token: %d %s", resp.StatusCode, body)
	}

	resp, body = e.do(http.MethodPut, "/api/v1/settings/vault", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": "https://other.test:8200", "authMethod": "token", "token": "t2"}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("changed address, fresh token: %d %s", resp.StatusCode, body)
	}
}

// TestVaultTestRequiresTokenOnAddressChange covers the same re-entry rule
// on POST /settings/vault/test (pre-flight ruling).
func TestVaultTestRequiresTokenOnAddressChange(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()

	resp, body := e.do(http.MethodPut, "/api/v1/settings/vault", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": "https://vault.test:8200", "authMethod": "token", "token": "t1"}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seed: %d %s", resp.StatusCode, body)
	}

	resp, body = e.do(http.MethodPost, "/api/v1/settings/vault/test", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": "https://other.test:8200", "authMethod": "token"}, csrf)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body), "re-enter the token") {
		t.Fatalf("changed address, omitted token: %d %s", resp.StatusCode, body)
	}

	resp, body = e.do(http.MethodPost, "/api/v1/settings/vault/test", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": "https://other.test:8200", "authMethod": "token", "token": "__unchanged__"}, csrf)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body), "re-enter the token") {
		t.Fatalf("changed address, __unchanged__ token: %d %s", resp.StatusCode, body)
	}

	// A fresh token on the changed address is well-formed: the request goes
	// through to the (unreachable) Vault, coming back 200 ok:false, not 422.
	resp, body = e.do(http.MethodPost, "/api/v1/settings/vault/test", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": "https://other.test:8200", "authMethod": "token", "token": "t2"}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("changed address, fresh token: %d %s", resp.StatusCode, body)
	}
	var res struct {
		Ok    bool    `json:"ok"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal(body, &res); err != nil || res.Ok {
		t.Fatalf("unreachable vault must be ok:false, not an error: %s (err %v)", body, err)
	}
}

// TestVaultSettingsUnchanged covers "__unchanged__" keeping the stored
// token: GET never reveals it, storedSecrets reports it held, and a PUT
// resending "__unchanged__" (with the address unchanged) keeps it in place.
func TestVaultSettingsUnchanged(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()

	resp, body := e.do(http.MethodPut, "/api/v1/settings/vault", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": "https://vault.test:8200", "authMethod": "token", "token": "s3cret-tok"}, csrf)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "s3cret-tok") {
		t.Fatalf("seed: %d %s", resp.StatusCode, body)
	}

	resp, body = e.do(http.MethodGet, "/api/v1/settings/vault", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "s3cret-tok") {
		t.Fatalf("get leaks secret: %d %s", resp.StatusCode, body)
	}
	var sec struct {
		StoredSecrets []string `json:"storedSecrets"`
	}
	if err := json.Unmarshal(body, &sec); err != nil || len(sec.StoredSecrets) != 1 || sec.StoredSecrets[0] != "token" {
		t.Fatalf("storedSecrets: %s (err %v)", body, err)
	}

	resp, body = e.do(http.MethodPut, "/api/v1/settings/vault", //nolint:bodyclose // testEnv.doRaw closes the body
		map[string]any{"address": "https://vault.test:8200", "authMethod": "token", "token": "__unchanged__"}, csrf)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "s3cret-tok") {
		t.Fatalf("unchanged token put: %d %s", resp.StatusCode, body)
	}

	vsec, ok := e.deps.Sections.Section(vault.SectionName)
	if !ok {
		t.Fatal("vault section not registered")
	}
	secrets, err := e.deps.Settings.SectionSecrets(context.Background(), vsec)
	if err != nil || secrets["token"] != "s3cret-tok" {
		t.Fatalf("token not preserved: %v err %v", secrets, err)
	}
}
