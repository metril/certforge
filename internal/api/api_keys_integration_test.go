//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

type createdKey struct {
	APIKey struct {
		ID     string   `json:"id"`
		Prefix string   `json:"prefix"`
		Scopes []string `json:"scopes"`
	} `json:"apiKey"`
	Token string `json:"token"`
}

func createKey(t *testing.T, e *testEnv, c *http.Client, csrf string, body map[string]any, want int) createdKey {
	t.Helper()
	resp, out := e.doClient(c, http.MethodPost, "/api/v1/api-keys", body, http.Header{"X-Csrf-Token": {csrf}}) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != want {
		t.Fatalf("create key: %d %s", resp.StatusCode, out)
	}
	var k createdKey
	_ = json.Unmarshal(out, &k)
	return k
}

func TestAPIKeys(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	org2, _ := e.deps.Queries.CreateOrg(context.Background(), sqlcgen.CreateOrgParams{Slug: "lab", Name: "Lab"})

	read := createKey(t, e, e.client, csrf, map[string]any{"name": "ci", "scopes": []string{"certs:read"}, "orgId": org}, http.StatusCreated)
	if len(read.APIKey.Prefix) != 12 || read.Token[:3] != "cf_" {
		t.Fatalf("key %+v", read)
	}
	resp, body := e.doBearer(read.Token, http.MethodGet, "/api/v1/orgs", nil) //nolint:bodyclose // doClient closes the body
	var orgs struct{ Items []struct{ ID uuid.UUID } }
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &orgs) != nil || len(orgs.Items) != 1 || orgs.Items[0].ID != org {
		t.Fatalf("org-scoped key sees %d %s (org2 %s)", resp.StatusCode, body, org2.ID)
	}
	if resp, _ := e.doBearer(read.Token, http.MethodGet, "/api/v1/users", nil); resp.StatusCode != http.StatusForbidden { //nolint:bodyclose // doClient closes the body
		t.Fatalf("users with certs:read key: %d", resp.StatusCode)
	}
	admin := createKey(t, e, e.client, csrf, map[string]any{"name": "ops", "scopes": []string{"admin"}}, http.StatusCreated)
	if resp, body := e.doBearer(admin.Token, http.MethodPut, "/api/v1/settings/general", map[string]string{}); resp.StatusCode != http.StatusOK { //nolint:bodyclose // doClient closes the body
		t.Fatalf("admin key write without CSRF: %d %s", resp.StatusCode, body)
	}
	var actorType, actorID string
	if err := e.deps.Pool.QueryRow(context.Background(), `SELECT actor_type, actor_id FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&actorType, &actorID); err != nil ||
		actorType != "apikey" || actorID != admin.APIKey.ID {
		t.Fatalf("audit actor %s %s %v", actorType, actorID, err)
	}
	if resp, _ := e.doBearer(admin.Token, http.MethodPost, "/api/v1/api-keys", map[string]any{"name": "x", "scopes": []string{"certs:read"}}); resp.StatusCode != http.StatusForbidden { //nolint:bodyclose // doClient closes the body
		t.Fatalf("key minting a key: %d", resp.StatusCode)
	}
	var used *string
	_ = e.deps.Pool.QueryRow(context.Background(), `SELECT last_used_at::text FROM api_keys WHERE id = $1`, admin.APIKey.ID).Scan(&used)
	if used == nil {
		t.Fatal("last_used_at not set")
	}
}

func TestAPIKeyScopeIntersection(t *testing.T) {
	e := newTestEnv(t)
	_, org := e.seedAdminSession()
	oa, oaCSRF, _ := e.userSession("olga", "org-admin", &org)
	k := createKey(t, e, oa, oaCSRF, map[string]any{"name": "ci", "scopes": []string{"admin", "certs:read", "keys:export"}, "orgId": org}, http.StatusCreated)
	if len(k.APIKey.Scopes) != 1 || k.APIKey.Scopes[0] != "certs:read" {
		t.Fatalf("scopes %v", k.APIKey.Scopes)
	}
	createKey(t, e, oa, oaCSRF, map[string]any{"name": "g", "scopes": []string{"certs:read"}}, http.StatusForbidden)
	createKey(t, e, oa, oaCSRF, map[string]any{"name": "x", "scopes": []string{"admin"}, "orgId": org}, http.StatusUnprocessableEntity)
	createKey(t, e, oa, oaCSRF, map[string]any{"name": "x", "scopes": []string{"root"}, "orgId": org}, http.StatusUnprocessableEntity)
	createKey(t, e, oa, oaCSRF, map[string]any{"name": "x", "scopes": []string{"certs:read"}, "orgId": org, "expiresAt": "2000-01-01T00:00:00Z"}, http.StatusUnprocessableEntity)
}

// TestAPIKeyVisibility covers a Task 9 review fold-in: an org-admin sees
// only its own org's keys, never another org's or a global one; an
// unauthorized ?orgId= is refused outright; and an org-scoped key is
// refused on another org's route.
func TestAPIKeyVisibility(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	org2, err := e.deps.Queries.CreateOrg(context.Background(), sqlcgen.CreateOrgParams{Slug: "lab", Name: "Lab"})
	if err != nil {
		t.Fatal(err)
	}
	oa, oaCSRF, _ := e.userSession("olga", "org-admin", &org)

	ownKey := createKey(t, e, oa, oaCSRF, map[string]any{"name": "own", "scopes": []string{"certs:read"}, "orgId": org}, http.StatusCreated)
	createKey(t, e, e.client, csrf, map[string]any{"name": "other", "scopes": []string{"certs:read"}, "orgId": org2.ID}, http.StatusCreated)
	createKey(t, e, e.client, csrf, map[string]any{"name": "glob", "scopes": []string{"certs:read"}}, http.StatusCreated)

	resp, body := e.doClient(oa, http.MethodGet, "/api/v1/api-keys", nil, nil) //nolint:bodyclose // doClient closes the body
	var list struct {
		Items []struct{ ID, Name string }
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &list) != nil {
		t.Fatalf("list %d %s", resp.StatusCode, body)
	}
	if len(list.Items) != 1 || list.Items[0].ID != ownKey.APIKey.ID {
		t.Fatalf("org-admin sees %+v, want only its own org's key", list.Items)
	}

	if resp, _ := e.doClient(oa, http.MethodGet, "/api/v1/api-keys?orgId="+org2.ID.String(), nil, nil); resp.StatusCode != http.StatusForbidden { //nolint:bodyclose // doClient closes the body
		t.Fatalf("?orgId= for another org without permission: %d", resp.StatusCode)
	}

	if resp, _ := e.doBearer(ownKey.Token, http.MethodGet, "/api/v1/api-keys?orgId="+org2.ID.String(), nil); resp.StatusCode != http.StatusForbidden { //nolint:bodyclose // doClient closes the body
		t.Fatalf("org-scoped key on another org's route: %d", resp.StatusCode)
	}
}

func TestAPIKeyRefusals(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	ctx := context.Background()
	c, cCSRF, creator := e.userSession("carl", "org-admin", &org)
	mk := func(name string) createdKey {
		return createKey(t, e, c, cCSRF, map[string]any{"name": name, "scopes": []string{"certs:read"}, "orgId": org}, http.StatusCreated)
	}
	ok := func(k createdKey) int {
		resp, _ := e.doBearer(k.Token, http.MethodGet, "/api/v1/orgs", nil) //nolint:bodyclose // doClient closes the body
		return resp.StatusCode
	}
	revoked, expired, orphan := mk("r"), mk("e"), mk("o")
	if resp, _ := e.do(http.MethodDelete, "/api/v1/api-keys/"+revoked.APIKey.ID, nil, csrf); resp.StatusCode != http.StatusNoContent { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("revoke %d", resp.StatusCode)
	}
	if resp, _ := e.do(http.MethodDelete, "/api/v1/api-keys/"+revoked.APIKey.ID, nil, csrf); resp.StatusCode != http.StatusNoContent { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("second revoke %d", resp.StatusCode)
	}
	if _, err := e.deps.Pool.Exec(ctx, `UPDATE api_keys SET expires_at = now() - interval '1 second' WHERE id = $1`, expired.APIKey.ID); err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]createdKey{"revoked": revoked, "expired": expired} {
		if got := ok(k); got != http.StatusUnauthorized {
			t.Fatalf("%s key: %d", name, got)
		}
	}
	if got := ok(orphan); got != http.StatusOK {
		t.Fatalf("live key: %d", got)
	}
	if err := e.deps.Queries.SetUserDisabled(ctx, sqlcgen.SetUserDisabledParams{ID: creator, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if got := ok(orphan); got != http.StatusUnauthorized {
		t.Fatalf("key of disabled creator: %d", got)
	}

	// B1: the API-key path is taken only for "Bearer cf_...". A malformed
	// cf_-shaped bearer is refused outright (401), even on a public route.
	if resp, _ := e.doClient(&http.Client{}, http.MethodGet, "/api/v1/setup/status", nil, http.Header{"Authorization": {"Bearer cf_0123456789ab_x"}}); resp.StatusCode != http.StatusUnauthorized { //nolint:bodyclose // doClient closes the body
		t.Fatalf("malformed cf_ bearer on a public route: %d", resp.StatusCode)
	}
	if resp, _ := e.doBearer("cf_0123456789ab_x", http.MethodGet, "/api/v1/orgs", nil); resp.StatusCode != http.StatusUnauthorized { //nolint:bodyclose // doClient closes the body
		t.Fatalf("malformed cf_ bearer on a private route: %d", resp.StatusCode)
	}

	// B1: any other scheme, or a Bearer token that isn't cf_-shaped (a
	// reverse proxy's Basic header, an upstream JWT), is ignored: the
	// request falls through to whatever cookie session it carries (none
	// here), so a public route still serves its normal response and a
	// private route still gets the ordinary "no session" 401.
	for _, h := range []string{"Bearer nope", "Basic abc"} {
		resp, _ := e.doClient(&http.Client{}, http.MethodGet, "/api/v1/setup/status", nil, http.Header{"Authorization": {h}}) //nolint:bodyclose // doClient closes the body
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%q ignored on a public route: %d", h, resp.StatusCode)
		}
		resp2, _ := e.doClient(&http.Client{}, http.MethodGet, "/api/v1/orgs", nil, http.Header{"Authorization": {h}}) //nolint:bodyclose // doClient closes the body
		if resp2.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%q ignored on a private route without a session: %d", h, resp2.StatusCode)
		}
	}
}

// TestAPIKeyPrecedence proves a valid bearer token wins over a cookie
// session carried on the very same request: the response reflects the
// key's own (narrower) authority, not the cookie's.
func TestAPIKeyPrecedence(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	read := createKey(t, e, e.client, csrf, map[string]any{"name": "narrow", "scopes": []string{"certs:read"}, "orgId": org}, http.StatusCreated)

	// e.client's jar still holds the admin session cookie (users:read is
	// within an admin's authority); attaching the certs:read-only bearer to
	// the same request must still be refused, proving the bearer decided
	// the outcome, not the cookie.
	resp, body := e.doClient(e.client, http.MethodGet, "/api/v1/users", nil, http.Header{"Authorization": {"Bearer " + read.Token}}) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bearer should have overridden the admin cookie: %d %s", resp.StatusCode, body)
	}

	// And a mutating request with the bearer attached needs no CSRF header
	// even though the same client also carries a cookie session (which
	// would otherwise require one).
	admin := createKey(t, e, e.client, csrf, map[string]any{"name": "ops2", "scopes": []string{"admin"}}, http.StatusCreated)
	resp2, body2 := e.doClient(e.client, http.MethodPut, "/api/v1/settings/general", map[string]string{}, http.Header{"Authorization": {"Bearer " + admin.Token}}) //nolint:bodyclose // doClient closes the body
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("bearer + cookie, no CSRF header: %d %s", resp2.StatusCode, body2)
	}
}

// TestAPIKeyMeIsSessionOnly covers M2: GET /auth/me returns the caller's
// session CSRF token, which an API key never has, so an authenticated
// API-key principal gets 403 ("session-only endpoint"), not 401 — 401 is
// reserved for no principal at all.
func TestAPIKeyMeIsSessionOnly(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	k := createKey(t, e, e.client, csrf, map[string]any{"name": "me-test", "scopes": []string{"certs:read"}, "orgId": org}, http.StatusCreated)

	resp, body := e.doBearer(k.Token, http.MethodGet, "/api/v1/auth/me", nil) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("api-key GET /auth/me: %d %s", resp.StatusCode, body)
	}
	var p struct{ Detail string }
	if err := json.Unmarshal(body, &p); err != nil || p.Detail != "session-only endpoint" {
		t.Fatalf("detail: %v %q", err, p.Detail)
	}
}

// TestRevokeApiKeyOutOfScopeIsNotFound covers M1: an org-admin who cannot
// see another org's API key gets 404 revoking it, worded exactly like a
// revoke of an id that doesn't exist at all — an unauthorized caller must
// not be able to distinguish "exists, but not mine" from "doesn't exist".
func TestRevokeApiKeyOutOfScopeIsNotFound(t *testing.T) {
	e := newTestEnv(t)
	csrf, orgA := e.seedAdminSession()
	orgB, err := e.deps.Queries.CreateOrg(context.Background(), sqlcgen.CreateOrgParams{Slug: "org-b", Name: "Org B"})
	if err != nil {
		t.Fatal(err)
	}
	keyA := createKey(t, e, e.client, csrf, map[string]any{"name": "a-key", "scopes": []string{"certs:read"}, "orgId": orgA}, http.StatusCreated)

	bClient, bCSRF2, _ := e.userSession("bob-b2", "org-admin", &orgB.ID)
	resp2, body2 := e.doClient(bClient, http.MethodDelete, "/api/v1/api-keys/"+keyA.APIKey.ID, nil, http.Header{"X-Csrf-Token": {bCSRF2}}) //nolint:bodyclose // doClient closes the body
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("org-admin revoking another org's key: %d %s", resp2.StatusCode, body2)
	}
	var outOfScope struct{ Detail string }
	if err := json.Unmarshal(body2, &outOfScope); err != nil {
		t.Fatal(err)
	}

	missingID := uuid.New()
	bClient2, bCSRF3, _ := e.userSession("bob-b3", "org-admin", &orgB.ID)
	resp3, body3 := e.doClient(bClient2, http.MethodDelete, "/api/v1/api-keys/"+missingID.String(), nil, http.Header{"X-Csrf-Token": {bCSRF3}}) //nolint:bodyclose // doClient closes the body
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("revoking a missing key: %d %s", resp3.StatusCode, body3)
	}
	var missing struct{ Detail string }
	if err := json.Unmarshal(body3, &missing); err != nil {
		t.Fatal(err)
	}

	wantOutOfScope := "API key " + keyA.APIKey.ID
	wantMissing := "API key " + missingID.String()
	if outOfScope.Detail != wantOutOfScope || missing.Detail != wantMissing {
		t.Fatalf("expected identically-worded 404s (only the id differs): out-of-scope=%q missing=%q", outOfScope.Detail, missing.Detail)
	}
}
