//go:build integration

package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/authn"
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
	var reason, method string
	row := e.deps.Pool.QueryRow(context.Background(),
		`SELECT details->>'reason', details->>'method' FROM audit_events WHERE action = 'session.login_failed' ORDER BY id DESC LIMIT 1`)
	if err := row.Scan(&reason, &method); err != nil || reason != "rate_limited" || method != "local" {
		t.Fatalf("session.login_failed audit row: reason=%q method=%q err=%v", reason, method, err)
	}
}

// TestRateLimitedAuditOncePerWindow: a burst of rejected logins from one
// client writes one audit row, not one per request (A4); the limit itself
// still rejects every request.
func TestRateLimitedAuditOncePerWindow(t *testing.T) {
	e := newTestEnvOpts(t, func(d *api.Deps) { d.LoginLimiter = authn.NewLimiter(1, 1) })
	seedAdminPassword(t, e, hardeningPw)
	e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": "wrong-password-1"}, "") //nolint:bodyclose // testEnv.doRaw closes the body
	for i := 0; i < 4; i++ {
		if resp, _ := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": "wrong-password-1"}, ""); resp.StatusCode != http.StatusTooManyRequests { //nolint:bodyclose // testEnv.doRaw closes the body
			t.Fatalf("attempt %d: %d", i+2, resp.StatusCode)
		}
	}
	var n int
	if err := e.deps.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'session.login_failed' AND details->>'reason' = 'rate_limited'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rate_limited audit rows = %d err=%v, want 1", n, err)
	}
}

// TestLoginRehashesOldParameters: a hash made with other argon2 parameters
// still verifies and is replaced by a current-parameter one on login (A20).
func TestLoginRehashesOldParameters(t *testing.T) {
	e := newTestEnv(t)
	seedAdminPassword(t, e, hardeningPw)
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(hardeningPw), salt, 2, 19456, 1, 32)
	old := fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	if _, err := e.deps.Pool.Exec(context.Background(), `UPDATE users SET local_password_hash = $1 WHERE local_password_hash IS NOT NULL`, old); err != nil {
		t.Fatal(err)
	}
	if resp, body := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": hardeningPw}, ""); resp.StatusCode != http.StatusOK { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("login: %d %s", resp.StatusCode, body)
	}
	var got string
	if err := e.deps.Pool.QueryRow(context.Background(), `SELECT local_password_hash FROM users WHERE local_password_hash IS NOT NULL`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if authn.NeedsRehash(got) || got == old {
		t.Fatalf("hash not upgraded: %s", got)
	}
	if resp, _ := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": hardeningPw}, ""); resp.StatusCode != http.StatusOK { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("login after rehash: %d", resp.StatusCode)
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
	resp2, _ := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": hardeningPw}, "") //nolint:bodyclose // testEnv.doRaw closes the body
	var newCookie string
	for _, c := range resp2.Cookies() {
		if c.Name == "cf_session" {
			newCookie = c.Value
		}
	}
	if newCookie == "" || newCookie == old {
		t.Fatalf("second login did not set a fresh session cookie: %q vs %q", newCookie, old)
	}
	if resp, _ := e.doWithCookie(http.MethodGet, "/api/v1/auth/me", old); resp.StatusCode != http.StatusUnauthorized { //nolint:bodyclose // doWithCookie closes the body
		t.Fatalf("old session still valid: %d", resp.StatusCode)
	}
	if resp, body := e.doWithCookie(http.MethodGet, "/api/v1/auth/me", newCookie); resp.StatusCode != http.StatusOK { //nolint:bodyclose // doWithCookie closes the body
		t.Fatalf("new session invalid: %d %s", resp.StatusCode, body)
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
	var m struct {
		OidcEnabled, LocalEnabled bool
		OidcCallbackURL           string
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &m) != nil || m.OidcEnabled || !m.LocalEnabled {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if !strings.HasSuffix(m.OidcCallbackURL, "/api/v1/auth/oidc/callback") {
		t.Fatalf("oidcCallbackUrl = %q", m.OidcCallbackURL)
	}
}
