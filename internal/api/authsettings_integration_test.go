//go:build integration

package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestAuthenticationSectionSecret(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	body := map[string]any{"enabled": true, "issuer": "https://idp.test", "clientId": "cf", "clientSecret": "s3cret"}
	resp, out := e.do(http.MethodPut, "/api/v1/settings/authentication", body, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || strings.Contains(string(out), "s3cret") || !strings.Contains(string(out), `"storedSecrets":["clientSecret"]`) {
		t.Fatalf("put %d %s", resp.StatusCode, out)
	}
	st, err := e.deps.AuthSettings.Get(context.Background())
	if err != nil || st.ClientSecret != "s3cret" || !st.OIDCReady() {
		t.Fatalf("source %+v %v", st, err)
	}
	resp, out = e.do(http.MethodPut, "/api/v1/settings/authentication", map[string]any{"enabled": true}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("enabled without issuer: %d %s", resp.StatusCode, out)
	}
}

func TestAuditIPHonoursTrustedProxies(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	lastIP := func() string {
		var ip string
		if err := e.deps.Pool.QueryRow(context.Background(), `SELECT ip FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&ip); err != nil {
			t.Fatal(err)
		}
		return ip
	}
	hdr := http.Header{"X-Forwarded-For": {"198.51.100.7"}, "X-Csrf-Token": {csrf}}
	e.doClient(e.client, http.MethodPut, "/api/v1/settings/general", map[string]string{}, hdr) //nolint:bodyclose // doClient closes the body
	if ip := lastIP(); ip != "127.0.0.1" {
		t.Fatalf("untrusted proxy: ip %q", ip)
	}
	resp, out := e.do(http.MethodPut, "/api/v1/settings/authentication", map[string]any{"trustedProxies": []string{"127.0.0.1"}}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put trustedProxies: %d %s", resp.StatusCode, out)
	}
	e.doClient(e.client, http.MethodPut, "/api/v1/settings/general", map[string]string{}, hdr) //nolint:bodyclose // doClient closes the body
	if ip := lastIP(); ip != "198.51.100.7" {
		t.Fatalf("trusted proxy: ip %q", ip)
	}
}
