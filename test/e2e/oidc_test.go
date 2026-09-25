//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const dexIssuer = "http://dex:5556/dex"

var formAction = regexp.MustCompile(`<form[^>]+action="([^"]+)"`)

// doRaw sends a session-cookie request and returns the raw response for
// callers that need the status code or body of a non-2xx or non-JSON
// response (call only handles the 2xx JSON case). The caller closes the
// body.
func (c *apiClient) doRaw(ctx context.Context, t *testing.T, method, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, baseURL()+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.csrf != "" && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp //nolint:bodyclose // caller closes the body
}

// bearerGet calls path with the given API key token in the Authorization
// header, on a client that carries no session cookie.
func bearerGet(ctx context.Context, t *testing.T, token, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL()+path, nil)
	if err != nil {
		t.Fatal(err)
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

// browser is a cookie-keeping client that does not follow redirects and
// reaches dex:5556 at CF_E2E_DEX_ADDR.
func browser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	dexAddr := envOr("CF_E2E_DEX_ADDR", "127.0.0.1:5556")
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "dex:5556" {
			addr = dexAddr
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	}
	return &http.Client{Jar: jar, Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// httpGet issues a context-bound GET, since noctx forbids the bare
// (*http.Client).Get/PostForm helpers this flow would otherwise read most
// naturally with.
func httpGet(ctx context.Context, t *testing.T, hc *http.Client, u string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp //nolint:bodyclose // callers close the body
}

// httpPostForm issues a context-bound, url-encoded form POST.
func httpPostForm(ctx context.Context, t *testing.T, hc *http.Client, u string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp //nolint:bodyclose // callers close the body
}

// follow GETs u and follows redirects while they stay on dex; it returns the
// last response body, its URL, and the first Location that leaves dex.
func follow(ctx context.Context, t *testing.T, b *http.Client, u string) (body string, at *url.URL, leave string) {
	t.Helper()
	for i := 0; i < 10; i++ {
		resp := httpGet(ctx, t, b, u)
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		at = resp.Request.URL
		loc := resp.Header.Get("Location")
		if loc == "" {
			return string(raw), at, ""
		}
		next, err := at.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		if next.Host != "dex:5556" {
			return string(raw), at, next.String()
		}
		u = next.String()
	}
	t.Fatal("too many redirects inside dex")
	return "", nil, ""
}

// TestOIDCLoginThroughDex drives the running certforge server (deploy/
// compose.test.yaml, which also runs the compose dex) through its HTTP API:
// configure single sign-on against dex, log in through dex's own local
// password form (a real browser-shaped auth-code round trip, never
// in-process), bind the new OIDC user a role, and check /auth/me, the
// session.login audit event and the audit chain. It then exercises the rest
// of Phase 2A's surface end to end: user disable, API key issue/bearer
// use/revoke, role binding list/delete, org/site CRUD, and audit list/
// export/verify.
func TestOIDCLoginThroughDex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin := newAPIClient(t)
	orgID := admin.authenticate(ctx, t)

	// Ruling C7: disable the login rate limit right after the first local
	// admin login and before any OIDC attempts, so repeated logins across
	// this test and the later Playwright suite (same compose stack) never
	// hit 429. A dedicated PUT first (the section does not exist yet, so
	// this alone fully defines it), then the full OIDC config below also
	// carries loginRatePerMinute explicitly rather than relying on it
	// merely being absent from that second PUT.
	admin.call(ctx, t, http.MethodPut, "/api/v1/settings/authentication", map[string]any{
		"loginRatePerMinute": 0,
	}, nil)

	admin.call(ctx, t, http.MethodPut, "/api/v1/settings/authentication", map[string]any{
		"enabled": true, "issuer": dexIssuer, "clientId": "certforge", "clientSecret": "certforge-e2e-secret",
		"scopes": []string{"openid", "profile", "email"}, "groupsClaim": "groups", "sessionTtlHours": 12,
		"trustedProxies": []string{}, "loginRatePerMinute": 0,
	}, nil)
	var test struct {
		Ok     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	waitFor(ctx, t, "dex discovery", func() (string, bool) {
		admin.call(ctx, t, http.MethodPost, "/api/v1/settings/authentication/test", map[string]string{"issuer": dexIssuer}, &test)
		return test.Detail, test.Ok
	})

	b := browser(t)
	resp := httpGet(ctx, t, b, baseURL()+"/api/v1/auth/oidc/start?next=/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), dexIssuer) {
		t.Fatalf("start: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	page, at, _ := follow(ctx, t, b, resp.Header.Get("Location"))
	m := formAction.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no login form at %s", at)
	}
	action, err := at.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	resp = httpPostForm(ctx, t, b, action.String(), url.Values{"login": {"oidc-user@example.test"}, "password": {"password"}})
	loginBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login form post: %d %.200s", resp.StatusCode, loginBody)
	}
	next, err := action.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("login form post: parse Location %q: %v", resp.Header.Get("Location"), err)
	}
	callback := next.String()
	if next.Host == "dex:5556" {
		_, _, callback = follow(ctx, t, b, next.String())
	}
	if !strings.Contains(callback, "/api/v1/auth/oidc/callback") {
		t.Fatalf("dex did not return to the callback: %q", callback)
	}
	resp = httpGet(ctx, t, b, callback)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	type me struct {
		User  struct{ ID, DisplayName string } `json:"user"`
		Roles []string                         `json:"roles"`
		Orgs  []struct{ ID string }            `json:"orgs"`
	}
	getMe := func() (me, int) {
		resp := httpGet(ctx, t, b, baseURL()+"/api/v1/auth/me")
		defer resp.Body.Close()
		var out me
		if resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatalf("me: decode: %v", err)
			}
		}
		return out, resp.StatusCode
	}
	first, code := getMe()
	if code != http.StatusOK || first.User.DisplayName != "oidc-user" || len(first.Roles) != 0 {
		t.Fatalf("new OIDC user %+v (status %d)", first, code)
	}

	// dex v2.45.1's builtin local (staticPasswords) connector does not
	// support a groups claim (upstream dexidp/dex#3958 is still open), so a
	// real password-form login can never carry a group to bind against. The
	// binding here is by the OIDC user's own subject id, exactly as a
	// non-group role binding works; oidc_group binding create/list/delete
	// is exercised structurally further down with a synthetic group name.
	// internal/authn's own unit/integration tests already cover the
	// oidc_group matching logic itself against the fake oidctest provider.
	var binding struct {
		ID string `json:"id"`
	}
	admin.call(ctx, t, http.MethodPost, "/api/v1/role-bindings", map[string]any{
		"subjectType": "user", "subject": first.User.ID, "role": "viewer", "orgId": orgID}, &binding)
	after, code := getMe()
	if code != http.StatusOK || !slices.Contains(after.Roles, "viewer") || len(after.Orgs) != 1 || after.Orgs[0].ID != orgID {
		t.Fatalf("binding not live: %+v (status %d)", after, code)
	}

	var events struct {
		Items []struct {
			Details map[string]any `json:"details"`
		} `json:"items"`
	}
	listResp := admin.doRaw(ctx, t, http.MethodGet, "/api/v1/audit?action=session.login&actor="+first.User.ID)
	if err := json.NewDecoder(listResp.Body).Decode(&events); err != nil {
		listResp.Body.Close()
		t.Fatalf("audit list: decode: %v", err)
	}
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("audit list: %d", listResp.StatusCode)
	}
	if v := listResp.Header.Get("X-Audit-Truncated"); v != "" {
		t.Fatalf("audit list: unexpected X-Audit-Truncated: %q (only the export sets it)", v)
	}
	if len(events.Items) == 0 || events.Items[0].Details["method"] != "oidc" {
		t.Fatalf("session.login not audited: %+v", events)
	}

	// Users: list, disable, and confirm the disabled user's session is dead.
	var users struct {
		Items []struct {
			ID       string `json:"id"`
			Disabled bool   `json:"disabled"`
		} `json:"items"`
	}
	admin.call(ctx, t, http.MethodGet, "/api/v1/users", nil, &users)
	if !slices.ContainsFunc(users.Items, func(u struct {
		ID       string `json:"id"`
		Disabled bool   `json:"disabled"`
	}) bool {
		return u.ID == first.User.ID && !u.Disabled
	}) {
		t.Fatalf("oidc user not listed enabled: %+v", users)
	}
	var disabled struct {
		Disabled bool `json:"disabled"`
	}
	admin.call(ctx, t, http.MethodPatch, "/api/v1/users/"+first.User.ID, map[string]any{"disabled": true}, &disabled)
	if !disabled.Disabled {
		t.Fatalf("user not disabled: %+v", disabled)
	}
	if _, code := getMe(); code != http.StatusUnauthorized {
		t.Fatalf("disabled user's session still works: status %d", code)
	}
	// Re-enable: the Phase 2B Playwright suite reuses this same compose
	// stack and this same oidc-user, so leaving it disabled here would
	// break that later sign-in.
	admin.call(ctx, t, http.MethodPatch, "/api/v1/users/"+first.User.ID, map[string]any{"disabled": false}, &disabled)
	if disabled.Disabled {
		t.Fatalf("user still disabled: %+v", disabled)
	}

	// API keys: create, call with the bearer token, revoke, confirm it stops
	// working.
	var created struct {
		APIKey struct {
			ID string `json:"id"`
		} `json:"apiKey"`
		Token string `json:"token"`
	}
	admin.call(ctx, t, http.MethodPost, "/api/v1/api-keys", map[string]any{
		"name": "e2e-oidc-key", "scopes": []string{"certs:read"}, "orgId": orgID,
	}, &created)
	if code, body := bearerGet(ctx, t, created.Token, "/api/v1/orgs/"+orgID+"/certificates"); code != http.StatusOK {
		t.Fatalf("bearer call: %d %s", code, body)
	}
	admin.call(ctx, t, http.MethodDelete, "/api/v1/api-keys/"+created.APIKey.ID, nil, nil)
	if code, body := bearerGet(ctx, t, created.Token, "/api/v1/orgs/"+orgID+"/certificates"); code != http.StatusUnauthorized {
		t.Fatalf("revoked key: got %d, want 401: %s", code, body)
	}

	// Role bindings: list finds the viewer binding, delete it; a synthetic
	// oidc_group binding exercises that subject type structurally (see the
	// comment above on dex's local connector not emitting groups).
	var bindings struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	admin.call(ctx, t, http.MethodGet, "/api/v1/role-bindings?orgId="+orgID, nil, &bindings)
	if !slices.ContainsFunc(bindings.Items, func(rb struct {
		ID string `json:"id"`
	}) bool {
		return rb.ID == binding.ID
	}) {
		t.Fatalf("viewer binding not listed: %+v", bindings)
	}
	admin.call(ctx, t, http.MethodDelete, "/api/v1/role-bindings/"+binding.ID, nil, nil)

	var groupBinding struct {
		ID string `json:"id"`
	}
	admin.call(ctx, t, http.MethodPost, "/api/v1/role-bindings", map[string]any{
		"subjectType": "oidc_group", "subject": "e2e-engineers", "role": "viewer", "orgId": orgID,
	}, &groupBinding)
	admin.call(ctx, t, http.MethodDelete, "/api/v1/role-bindings/"+groupBinding.ID, nil, nil)

	// Orgs and sites CRUD.
	var org2 struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	admin.call(ctx, t, http.MethodPost, "/api/v1/orgs", map[string]any{"slug": "e2e-oidc", "name": "E2E OIDC"}, &org2)
	admin.call(ctx, t, http.MethodPatch, "/api/v1/orgs/"+org2.ID, map[string]any{"name": "E2E OIDC Renamed"}, &org2)
	if org2.Name != "E2E OIDC Renamed" {
		t.Fatalf("org rename: %+v", org2)
	}
	var site struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	admin.call(ctx, t, http.MethodPost, "/api/v1/orgs/"+org2.ID+"/sites", map[string]any{"name": "site-a"}, &site)
	admin.call(ctx, t, http.MethodPatch, "/api/v1/orgs/"+org2.ID+"/sites/"+site.ID, map[string]any{"name": "site-a-renamed"}, &site)
	if site.Name != "site-a-renamed" {
		t.Fatalf("site rename: %+v", site)
	}
	admin.call(ctx, t, http.MethodDelete, "/api/v1/orgs/"+org2.ID+"/sites/"+site.ID, nil, nil)
	admin.call(ctx, t, http.MethodDelete, "/api/v1/orgs/"+org2.ID, nil, nil)

	// Audit: export as CSV, then verify the chain last of all.
	expResp := admin.doRaw(ctx, t, http.MethodGet, "/api/v1/audit/export")
	expBody, err := io.ReadAll(expResp.Body)
	expResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if expResp.StatusCode != http.StatusOK || !strings.HasPrefix(expResp.Header.Get("Content-Type"), "text/csv") ||
		!strings.HasPrefix(string(expBody), "id,ts,actor_type,") {
		t.Fatalf("audit export: %d %q %.100s", expResp.StatusCode, expResp.Header.Get("Content-Type"), expBody)
	}
	// The handler always sets X-Audit-Truncated (never omits it; see
	// internal/api/audit.go and internal/api/audit_integration_test.go's
	// own TestAuditExportNeutralizesFormulas, which checks the same
	// "false"), so a literal absence check would always fail here — this
	// e2e run is well under the 100000-row cap, so the header must read
	// "false".
	if v := expResp.Header.Get("X-Audit-Truncated"); v != "false" {
		t.Fatalf("audit export: X-Audit-Truncated = %q, want %q (this run is nowhere near the 100000-row cap)", v, "false")
	}

	var chain struct {
		Ok bool `json:"ok"`
	}
	admin.call(ctx, t, http.MethodGet, "/api/v1/audit/verify", nil, &chain)
	if !chain.Ok {
		t.Fatal("audit chain broken after e2e run")
	}
}
