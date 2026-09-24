//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/authn"
)

func TestSetupHTTP(t *testing.T) {
	e := newTestEnv(t)
	_, body := e.do(http.MethodGet, "/api/v1/setup/status", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if !strings.Contains(string(body), `"needsSetup":true`) {
		t.Fatalf("status %s", body)
	}
	in := map[string]string{"adminPassword": "correct horse battery", "orgName": "Home", "orgSlug": "home", "baseUrl": "http://example.test"}

	resp, _ := e.doRaw(http.MethodPost, "/api/v1/setup/complete", "text/plain", `{"adminPassword":"x"}`, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain %d", resp.StatusCode)
	}
	bad := map[string]string{"adminPassword": "short", "orgName": "Home", "orgSlug": "home", "baseUrl": "http://example.test"}
	if resp, _ = e.do(http.MethodPost, "/api/v1/setup/complete", bad, ""); resp.StatusCode != http.StatusUnprocessableEntity { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("invalid %d", resp.StatusCode)
	}

	resp, body = e.do(http.MethodPost, "/api/v1/setup/complete", in, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("complete %d %s", resp.StatusCode, body)
	}
	var me meBody
	if err := json.Unmarshal(body, &me); err != nil || me.CsrfToken == "" || len(me.Orgs) != 1 || me.Orgs[0].Slug != "home" {
		t.Fatalf("me %s", body)
	}
	if resp, _ = e.do(http.MethodGet, "/api/v1/auth/me", nil, ""); resp.StatusCode != http.StatusOK { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("session not started: %d", resp.StatusCode)
	}
	if resp, _ = e.do(http.MethodPost, "/api/v1/setup/complete", in, me.CsrfToken); resp.StatusCode != http.StatusConflict { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("second complete %d", resp.StatusCode)
	}
	_, body = e.do(http.MethodGet, "/api/v1/setup/status", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if !strings.Contains(string(body), `"needsSetup":false`) {
		t.Fatalf("status after %s", body)
	}
}

func TestCompleteSetupArgonBusy(t *testing.T) {
	e := newTestEnv(t)
	restore := authn.SetArgonConcurrency(1)
	defer restore()
	release, ok := authn.TryAcquireArgonSlot()
	if !ok {
		t.Fatal("could not acquire the only argon2 slot")
	}
	defer release()
	in := map[string]string{"adminPassword": "correct horse battery", "orgName": "Home", "orgSlug": "home", "baseUrl": "http://example.test"}
	resp, _ := e.do(http.MethodPost, "/api/v1/setup/complete", in, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("code %d", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra != "1" {
		t.Fatalf("retry-after %q", ra)
	}
}
