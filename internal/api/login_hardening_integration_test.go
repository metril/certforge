//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/metril/certforge/internal/api"
)

const hardeningPw = "correct horse battery staple"

func TestLoginRateLimited(t *testing.T) {
	e := newTestEnvOpts(t, func(d *api.Deps) { d.LoginLimiter = nil })
	seedAdminPassword(t, e, hardeningPw)
	for i := 0; i < 5; i++ {
		if resp, _ := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": "wrong-password-1"}, ""); resp.StatusCode != http.StatusUnauthorized { //nolint:bodyclose // testEnv.doRaw closes the body
			t.Fatalf("attempt %d: %d", i+1, resp.StatusCode)
		}
	}
	resp, body := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": hardeningPw}, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("6th: %d %s", resp.StatusCode, body)
	}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil || s < 1 {
		t.Fatalf("Retry-After %q", resp.Header.Get("Retry-After"))
	}
}

func TestLoginWithStaleSessionNeedsNoCSRF(t *testing.T) {
	e := newTestEnv(t)
	seedAdminPassword(t, e, hardeningPw)
	for i := 0; i < 2; i++ {
		if resp, body := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": hardeningPw}, ""); resp.StatusCode != http.StatusOK { //nolint:bodyclose // testEnv.doRaw closes the body
			t.Fatalf("login %d: %d %s", i+1, resp.StatusCode, body)
		}
	}
}

func TestNewLoginRevokesOldSessions(t *testing.T) {
	e := newTestEnv(t)
	seedAdminPassword(t, e, hardeningPw)
	resp, _ := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": hardeningPw}, "") //nolint:bodyclose // testEnv.doRaw closes the body
	var old string
	for _, c := range resp.Cookies() {
		if c.Name == "cf_session" {
			old = c.Value
		}
	}
	e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": hardeningPw}, "")                        //nolint:bodyclose // testEnv.doRaw closes the body
	if resp, _ := e.doWithCookie(http.MethodGet, "/api/v1/auth/me", old); resp.StatusCode != http.StatusUnauthorized { //nolint:bodyclose // doWithCookie closes the body
		t.Fatalf("old session still valid: %d", resp.StatusCode)
	}
	var n int
	if err := e.deps.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'session.revoked'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("session.revoked events %d %v", n, err)
	}
}

func TestSessionTTLFromSettings(t *testing.T) {
	e := newTestEnv(t)
	seedAdminPassword(t, e, hardeningPw)
	_, body := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": hardeningPw}, "") //nolint:bodyclose // testEnv.doRaw closes the body
	var me struct {
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatal(err)
	}
	e.do(http.MethodPut, "/api/v1/settings/authentication", map[string]any{"sessionTtlHours": 1}, me.CsrfToken) //nolint:bodyclose // testEnv.doRaw closes the body
	e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": hardeningPw}, "")                 //nolint:bodyclose // testEnv.doRaw closes the body
	var exp time.Time
	if err := e.deps.Pool.QueryRow(context.Background(), `SELECT max(expires_at) FROM sessions`).Scan(&exp); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d > time.Hour+time.Minute || d < time.Hour-time.Minute {
		t.Fatalf("session lasts %v", d)
	}
}

func TestAuthMethods(t *testing.T) {
	e := newTestEnv(t)
	seedAdminPassword(t, e, hardeningPw)
	resp, body := e.do(http.MethodGet, "/api/v1/auth/methods", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	var m struct{ OidcEnabled, LocalEnabled bool }
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &m) != nil || m.OidcEnabled || !m.LocalEnabled {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}
