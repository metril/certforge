//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authn/oidctest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// enableOIDC points the authentication section at fake.
func enableOIDC(t *testing.T, e *testEnv, csrf string, fake *oidctest.Provider) {
	t.Helper()
	resp, body := e.do(http.MethodPut, "/api/v1/settings/authentication", map[string]any{ //nolint:bodyclose // testEnv.doRaw closes the body
		"enabled": true, "issuer": fake.URL(), "clientId": oidctest.ClientID, "clientSecret": oidctest.ClientSecret,
	}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable oidc: %d %s", resp.StatusCode, body)
	}
}

// oidcLogin runs start → fake authorize → callback in a fresh browser and
// returns that browser and the callback's Location.
func oidcLogin(t *testing.T, e *testEnv, next string) (*http.Client, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	b := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := e.doClient(b, http.MethodGet, "/api/v1/auth/oidc/start?next="+url.QueryEscape(next), nil, nil) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	idp, err := b.Get(resp.Header.Get("Location")) //nolint:noctx // test helper follows a redirect from a canned response
	if err != nil {
		t.Fatal(err)
	}
	idp.Body.Close()
	cb, err := url.Parse(idp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	// The redirect URI is built from the configured base URL
	// (http://example.test); deliver it to the test server instead.
	resp, _ = e.doClient(b, http.MethodGet, cb.Path+"?"+cb.RawQuery, nil, nil) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	return b, resp.Header.Get("Location")
}

func TestOIDCLogin(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	fake := oidctest.New(t)
	fake.SetUser(oidctest.User{Subject: "u1", Email: "ann@example.test", Name: "Ann", Groups: []string{"ops"}})
	enableOIDC(t, e, csrf, fake)
	if err := e.deps.Queries.CreateRoleBinding(context.Background(), sqlcgen.CreateRoleBindingParams{
		SubjectType: "oidc_group", Subject: "ops", Role: "viewer", OrgID: &org}); err != nil {
		t.Fatal(err)
	}
	b, loc := oidcLogin(t, e, "/o/home/overview")
	if loc != "/o/home/overview" {
		t.Fatalf("location %q", loc)
	}
	resp, body := e.doClient(b, http.MethodGet, "/api/v1/auth/me", nil, nil) //nolint:bodyclose // doClient closes the body
	var me meBody
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &me) != nil || me.User.DisplayName != "Ann" ||
		len(me.Roles) != 1 || me.Roles[0] != "viewer" || me.User.LocalAdmin {
		t.Fatalf("me %d %s", resp.StatusCode, body)
	}
	// The second login updates the same user and revokes the first session.
	fake.SetUser(oidctest.User{Subject: "u1", Email: "ann@example.test", Name: "Ann B"})
	oidcLogin(t, e, "/")
	if resp, _ := e.doClient(b, http.MethodGet, "/api/v1/auth/me", nil, nil); resp.StatusCode != http.StatusUnauthorized { //nolint:bodyclose // doClient closes the body
		t.Fatalf("first session survived: %d", resp.StatusCode)
	}
	var n int
	if err := e.deps.Pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE oidc_sub = 'u1'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("users with sub u1: %d %v", n, err)
	}
	var groups []string
	if err := e.deps.Pool.QueryRow(context.Background(), `SELECT oidc_groups FROM users WHERE oidc_sub = 'u1'`).Scan(&groups); err != nil || len(groups) != 0 {
		t.Fatalf("groups not refreshed: %v %v", groups, err)
	}
}

func TestOIDCNextIsSanitized(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	enableOIDC(t, e, csrf, oidctest.New(t))
	for _, next := range []string{
		"//evil.example", "https://evil.example/x", `/\evil.example`, "javascript:alert(1)", "evil", "",
		"/\t/evil", "/%2F%2Fevil", "/%5Cevil", "/" + strings.Repeat("a", 2048), "/\\evil.example",
	} {
		if _, loc := oidcLogin(t, e, next); loc != "/" {
			t.Fatalf("next %q → %q", next, loc)
		}
	}
	if _, loc := oidcLogin(t, e, "/o/home/certificates?status=failed"); loc != "/o/home/certificates?status=failed" {
		t.Fatalf("same-origin path lost: %q", loc)
	}
}

func TestOIDCFailuresRedirectToLogin(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	fake := oidctest.New(t)
	enableOIDC(t, e, csrf, fake)

	fake.SetDenied(true)
	if _, loc := oidcLogin(t, e, "/"); loc != "/login?error=oidc_denied" {
		t.Fatalf("denied → %q", loc)
	}
	fake.SetDenied(false)

	fake.SetUser(oidctest.User{Subject: "off", Name: "Off"})
	oidcLogin(t, e, "/")
	if _, err := e.deps.Pool.Exec(context.Background(), `UPDATE users SET disabled = true WHERE oidc_sub = 'off'`); err != nil {
		t.Fatal(err)
	}
	if _, loc := oidcLogin(t, e, "/"); loc != "/login?error=user_disabled" {
		t.Fatalf("disabled → %q", loc)
	}

	resp, _ := e.doClient(&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, //nolint:bodyclose // doClient closes the body
		http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=y", nil, nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login?error=oidc_state" {
		t.Fatalf("no state cookie → %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestOIDCStartWhenDisabled(t *testing.T) {
	e := newTestEnv(t)
	b := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := e.doClient(b, http.MethodGet, "/api/v1/auth/oidc/start", nil, nil) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login?error=oidc_disabled" {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAuthenticationTestEndpoint(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	fake := oidctest.New(t)
	resp, body := e.do(http.MethodPost, "/api/v1/settings/authentication/test", map[string]string{"issuer": fake.URL()}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ok":true`) || !strings.Contains(string(body), `"keys":1`) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	resp, body = e.do(http.MethodPost, "/api/v1/settings/authentication/test", map[string]string{"issuer": "http://127.0.0.1:1"}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ok":false`) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

// TestOIDCRateLimited exercises the callback's 429 path (B2/E3): once the
// per-client budget is spent, even the callback redirects to /login rather
// than returning problem+json to a browser navigation.
func TestOIDCRateLimited(t *testing.T) {
	e := newTestEnvOpts(t, func(d *api.Deps) { d.LoginLimiter = authn.NewLimiter(1, 1) })
	csrf, _ := e.seedAdminSession()
	fake := oidctest.New(t)
	fake.SetUser(oidctest.User{Subject: "rl1"})
	enableOIDC(t, e, csrf, fake)
	oidcLogin(t, e, "/") // spends the single allowed callback
	if _, loc := oidcLogin(t, e, "/"); loc != "/login?error=rate_limited" {
		t.Fatalf("rate limited → %q", loc)
	}
}

// TestOIDCTokenEndpointDown exercises the callback's failure path (E3) when
// the identity provider's token endpoint is unreachable: the discovery
// document was already fetched and cached during start, but the code
// exchange itself fails, which must still redirect to /login, not 500.
func TestOIDCTokenEndpointDown(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	fake := oidctest.New(t)
	enableOIDC(t, e, csrf, fake)

	jar, _ := cookiejar.New(nil)
	b := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := e.doClient(b, http.MethodGet, "/api/v1/auth/oidc/start?next=%2F", nil, nil) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	idp, err := b.Get(resp.Header.Get("Location")) //nolint:noctx // test helper follows a redirect from a canned response
	if err != nil {
		t.Fatal(err)
	}
	idp.Body.Close()
	cb, err := url.Parse(idp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	fake.Stop()                                                                // the token endpoint is now unreachable
	resp, _ = e.doClient(b, http.MethodGet, cb.Path+"?"+cb.RawQuery, nil, nil) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login?error=oidc_failed" {
		t.Fatalf("token endpoint down → %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// TestOIDCCallbackDBErrorRedirects exercises the callback's remaining E3
// failure path: a database error after the identity provider has already
// confirmed the login must still redirect to /login, not 500. The
// authentication section is cached for 30s (authn.SettingsSource), so
// closing the pool right before the callback leaves discovery/exchange
// (both pure HTTP calls to the fake provider) unaffected and fails exactly
// the user-upsert query this is meant to exercise.
func TestOIDCCallbackDBErrorRedirects(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	fake := oidctest.New(t)
	fake.SetUser(oidctest.User{Subject: "db-error"})
	enableOIDC(t, e, csrf, fake)

	jar, _ := cookiejar.New(nil)
	b := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := e.doClient(b, http.MethodGet, "/api/v1/auth/oidc/start?next=%2F", nil, nil) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	idp, err := b.Get(resp.Header.Get("Location")) //nolint:noctx // test helper follows a redirect from a canned response
	if err != nil {
		t.Fatal(err)
	}
	idp.Body.Close()
	cb, err := url.Parse(idp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	e.deps.Pool.Close()                                                        // the user upsert (and everything else DB-backed) now fails
	resp, _ = e.doClient(b, http.MethodGet, cb.Path+"?"+cb.RawQuery, nil, nil) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login?error=oidc_failed" {
		t.Fatalf("db error → %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// TestAuthenticationTestEndpointForbidden confirms settings:write (admin
// only) gates the connection test: a lower role must never be able to make
// the server fetch an admin-supplied URL.
func TestAuthenticationTestEndpointForbidden(t *testing.T) {
	e := newTestEnv(t)
	resp, _ := e.do(http.MethodPost, "/api/v1/settings/authentication/test", map[string]string{"issuer": "http://127.0.0.1:1"}, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", resp.StatusCode)
	}

	csrf, org := e.seedAdminSession()
	fake := oidctest.New(t)
	fake.SetUser(oidctest.User{Subject: "viewer1", Groups: []string{"ro"}})
	enableOIDC(t, e, csrf, fake)
	if err := e.deps.Queries.CreateRoleBinding(context.Background(), sqlcgen.CreateRoleBindingParams{
		SubjectType: "oidc_group", Subject: "ro", Role: "viewer", OrgID: &org}); err != nil {
		t.Fatal(err)
	}
	b, _ := oidcLogin(t, e, "/")
	meResp, meRaw := e.doClient(b, http.MethodGet, "/api/v1/auth/me", nil, nil) //nolint:bodyclose // doClient closes the body
	var mb meBody
	if meResp.StatusCode != http.StatusOK || json.Unmarshal(meRaw, &mb) != nil {
		t.Fatalf("viewer me: %d %s", meResp.StatusCode, meRaw)
	}
	hdr := http.Header{authn.CSRFHeader: []string{mb.CsrfToken}}
	resp, _ = e.doClient(b, http.MethodPost, "/api/v1/settings/authentication/test", //nolint:bodyclose // doClient closes the body
		map[string]string{"issuer": "http://127.0.0.1:1"}, hdr)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer: %d", resp.StatusCode)
	}
}

// TestOIDCStateCookieAttributes checks the cf_oidc state cookie's shape
// (HttpOnly, SameSite=Lax, scoped to /api/v1/auth/oidc, Secure when the
// request came from a trusted proxy terminating TLS) and that both a
// successful and a failed callback clear it.
func TestOIDCStateCookieAttributes(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	fake := oidctest.New(t)
	fake.SetUser(oidctest.User{Subject: "cookie-test"})
	// One PUT: settings/{section} replaces the whole section, so
	// trustedProxies must ride along with enabling OIDC, not a separate call.
	resp, out := e.do(http.MethodPut, "/api/v1/settings/authentication", map[string]any{ //nolint:bodyclose // testEnv.doRaw closes the body
		"enabled": true, "issuer": fake.URL(), "clientId": oidctest.ClientID, "clientSecret": oidctest.ClientSecret,
		"trustedProxies": []string{"127.0.0.1/32", "::1/128"},
	}, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable oidc + trustedProxies: %d %s", resp.StatusCode, out)
	}

	jar, _ := cookiejar.New(nil)
	b := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	hdr := http.Header{"X-Forwarded-Proto": {"https"}}
	resp, _ = e.doClient(b, http.MethodGet, "/api/v1/auth/oidc/start", nil, hdr) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	state := findCookie(resp, authn.StateCookieName)
	if state == nil || !state.HttpOnly || state.SameSite != http.SameSiteLaxMode ||
		state.Path != "/api/v1/auth/oidc" || !state.Secure {
		t.Fatalf("state cookie %+v", state)
	}

	idp, err := b.Get(resp.Header.Get("Location")) //nolint:noctx // test helper follows a redirect from a canned response
	if err != nil {
		t.Fatal(err)
	}
	idp.Body.Close()
	cb, err := url.Parse(idp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ = e.doClient(b, http.MethodGet, cb.Path+"?"+cb.RawQuery, nil, hdr) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	if cleared := findCookie(resp, authn.StateCookieName); cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("state cookie not cleared on success: %+v", cleared)
	}

	// A failed callback (no valid state cookie this time round) clears it too.
	resp, _ = e.doClient(b, http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=y", nil, hdr) //nolint:bodyclose // doClient closes the body
	if cleared := findCookie(resp, authn.StateCookieName); cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("state cookie not cleared on failure: %+v", cleared)
	}
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
