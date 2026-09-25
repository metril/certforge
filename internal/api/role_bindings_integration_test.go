//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

type bindingOut struct {
	ID           string  `json:"id"`
	SubjectType  string  `json:"subjectType"`
	Subject      string  `json:"subject"`
	SubjectLabel string  `json:"subjectLabel"`
	Role         string  `json:"role"`
	OrgID        *string `json:"orgId"`
}

func listBindings(t *testing.T, e *testEnv, c *http.Client) []bindingOut {
	t.Helper()
	resp, body := e.doClient(c, http.MethodGet, "/api/v1/role-bindings", nil, nil) //nolint:bodyclose // doClient closes the body
	var l struct{ Items []bindingOut }
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &l) != nil {
		t.Fatalf("list %d %s", resp.StatusCode, body)
	}
	return l.Items
}

func TestRoleBindings(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	org2, _ := e.deps.Queries.CreateOrg(context.Background(), sqlcgen.CreateOrgParams{Slug: "lab", Name: "Lab"})
	bob, _, bobID := e.userSession("bob", "", nil)
	_, _, victimID := e.userSession("vic", "", nil)
	oa, oaCSRF, _ := e.userSession("olga", "org-admin", &org)
	post := func(c *http.Client, csrf string, body map[string]any) (int, bindingOut) {
		resp, out := e.doClient(c, http.MethodPost, "/api/v1/role-bindings", body, http.Header{"X-Csrf-Token": {csrf}}) //nolint:bodyclose // doClient closes the body
		var b bindingOut
		_ = json.Unmarshal(out, &b)
		return resp.StatusCode, b
	}
	code, b := post(e.client, csrf, map[string]any{"subjectType": "user", "subject": bobID.String(), "role": "viewer", "orgId": org})
	if code != http.StatusCreated || b.SubjectLabel != "bob" {
		t.Fatalf("create %d %+v", code, b)
	}
	_, body := e.doClient(bob, http.MethodGet, "/api/v1/auth/me", nil, nil) //nolint:bodyclose // doClient closes the body
	var me meBody
	if err := json.Unmarshal(body, &me); err != nil || len(me.Roles) != 1 || me.Roles[0] != "viewer" {
		t.Fatalf("binding not live: %s", body)
	}
	for name, tc := range map[string]struct {
		c    *http.Client
		csrf string
		body map[string]any
		want int
	}{
		"duplicate":    {e.client, csrf, map[string]any{"subjectType": "user", "subject": bobID.String(), "role": "viewer", "orgId": org}, http.StatusConflict},
		"unknown user": {e.client, csrf, map[string]any{"subjectType": "user", "subject": uuid.NewString(), "role": "viewer"}, http.StatusUnprocessableEntity},
		"bad role":     {e.client, csrf, map[string]any{"subjectType": "oidc_group", "subject": "ops", "role": "root"}, http.StatusUnprocessableEntity},
		"bad type":     {e.client, csrf, map[string]any{"subjectType": "team", "subject": "ops", "role": "viewer"}, http.StatusUnprocessableEntity},
		// D1: oidc_group bindings are admin-only (global bindings:write),
		// even when targeting the org-admin's own org.
		"org-admin oidc_group own org": {oa, oaCSRF, map[string]any{"subjectType": "oidc_group", "subject": "ops", "role": "operator", "orgId": org}, http.StatusForbidden},
		"org-admin oidc_group global":  {oa, oaCSRF, map[string]any{"subjectType": "oidc_group", "subject": "ops", "role": "viewer"}, http.StatusForbidden},
		"admin oidc_group global":      {e.client, csrf, map[string]any{"subjectType": "oidc_group", "subject": "ops", "role": "operator"}, http.StatusCreated},
		// D1: org-admins manage user bindings within their own org only.
		"org-admin user own org":   {oa, oaCSRF, map[string]any{"subjectType": "user", "subject": victimID.String(), "role": "viewer", "orgId": org}, http.StatusCreated},
		"org-admin user other org": {oa, oaCSRF, map[string]any{"subjectType": "user", "subject": victimID.String(), "role": "viewer", "orgId": org2.ID}, http.StatusForbidden},
		"org-admin user global":    {oa, oaCSRF, map[string]any{"subjectType": "user", "subject": victimID.String(), "role": "viewer"}, http.StatusForbidden},
	} {
		if code, _ := post(tc.c, tc.csrf, tc.body); code != tc.want {
			t.Fatalf("%s: %d, want %d", name, code, tc.want)
		}
	}
	for _, b := range listBindings(t, e, oa) {
		if b.OrgID == nil || *b.OrgID != org.String() {
			t.Fatalf("org-admin sees %+v", b)
		}
	}
}

// TestRoleBindingsAPIKeyScope proves C9: apikey bindings are gated by
// apikeys:write at the key's own scope (global for a global key, the key's
// org for an org-scoped key), not by bindings:write at the request's orgId.
func TestRoleBindingsAPIKeyScope(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	oa, oaCSRF, _ := e.userSession("olga", "org-admin", &org)

	globalKey := createKey(t, e, e.client, csrf, map[string]any{"name": "global", "scopes": []string{"certs:read"}}, http.StatusCreated)
	orgKey := createKey(t, e, e.client, csrf, map[string]any{"name": "org", "scopes": []string{"certs:read"}, "orgId": org}, http.StatusCreated)

	post := func(c *http.Client, csrf string, body map[string]any) (int, bindingOut) {
		resp, out := e.doClient(c, http.MethodPost, "/api/v1/role-bindings", body, http.Header{"X-Csrf-Token": {csrf}}) //nolint:bodyclose // doClient closes the body
		var b bindingOut
		_ = json.Unmarshal(out, &b)
		return resp.StatusCode, b
	}

	// The org-admin lacks apikeys:write globally, so it cannot bind the
	// global key even though it holds bindings:write in its own org.
	if code, _ := post(oa, oaCSRF, map[string]any{"subjectType": "apikey", "subject": globalKey.APIKey.ID, "role": "viewer"}); code != http.StatusForbidden {
		t.Fatalf("org-admin binding global key: %d", code)
	}
	// The org-admin holds apikeys:write in its own org, so it may bind the
	// org-scoped key there.
	code, b := post(oa, oaCSRF, map[string]any{"subjectType": "apikey", "subject": orgKey.APIKey.ID, "role": "viewer", "orgId": org})
	if code != http.StatusCreated || b.SubjectLabel != "org" {
		t.Fatalf("org-admin binding own-org key: %d %+v", code, b)
	}
	// The global admin may delete it (apikeys:write at the key's own org).
	if resp, _ := e.do(http.MethodDelete, "/api/v1/role-bindings/"+b.ID, nil, csrf); resp.StatusCode != http.StatusNoContent { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("delete apikey binding: %d", resp.StatusCode)
	}
	// The org-admin cannot delete a binding on the global key (again,
	// apikeys:write is required globally, which it lacks).
	code, gb := post(e.client, csrf, map[string]any{"subjectType": "apikey", "subject": globalKey.APIKey.ID, "role": "viewer"})
	if code != http.StatusCreated {
		t.Fatalf("admin binding global key: %d", code)
	}
	if resp, _ := e.doClient(oa, http.MethodDelete, "/api/v1/role-bindings/"+gb.ID, nil, http.Header{"X-Csrf-Token": {oaCSRF}}); resp.StatusCode != http.StatusForbidden { //nolint:bodyclose // doClient closes the body
		t.Fatalf("org-admin deleting global key binding: %d", resp.StatusCode)
	}
}

func globalAdminBindingOf(t *testing.T, e *testEnv, subject string) string {
	t.Helper()
	for _, b := range listBindings(t, e, e.client) {
		if b.Role == "admin" && b.OrgID == nil && b.Subject == subject {
			return b.ID
		}
	}
	t.Fatalf("no global admin binding for %s", subject)
	return ""
}

func TestDeleteLastGlobalAdminBinding(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	admin, _ := e.deps.Queries.GetLocalAdmin(context.Background())
	own := globalAdminBindingOf(t, e, admin.ID.String())
	if resp, _ := e.do(http.MethodDelete, "/api/v1/role-bindings/"+own, nil, csrf); resp.StatusCode != http.StatusConflict { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("last admin: %d", resp.StatusCode)
	}
	_, _, second := e.userSession("sam", "admin", nil)
	if resp, _ := e.do(http.MethodDelete, "/api/v1/role-bindings/"+globalAdminBindingOf(t, e, second.String()), nil, csrf); resp.StatusCode != http.StatusNoContent { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("second admin: %d", resp.StatusCode)
	}
}

func TestConcurrentAdminBindingDeletes(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	admin, _ := e.deps.Queries.GetLocalAdmin(context.Background())
	samClient, samCSRF, second := e.userSession("sam", "admin", nil)
	// Each admin deletes its own binding, using its own session: a caller
	// deleting the OTHER caller's binding would strip that other session's
	// own authority mid-test (its principal is reloaded fresh from the DB
	// on its next request), racing the outcome on request-arrival order
	// rather than proving the LockGlobalUserAdminBindings serialization
	// this test targets.
	type call struct {
		c    *http.Client
		csrf string
		id   string
	}
	calls := []call{
		{e.client, csrf, globalAdminBindingOf(t, e, admin.ID.String())},
		{samClient, samCSRF, globalAdminBindingOf(t, e, second.String())},
	}
	codes := make([]int, 2)
	var wg, ready sync.WaitGroup
	start := make(chan struct{})
	ready.Add(2)
	for i, cl := range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, e.srv.URL+"/api/v1/role-bindings/"+cl.id, nil)
			if err != nil {
				t.Error(err)
				return
			}
			req.Header.Set("X-CSRF-Token", cl.csrf)
			ready.Done()
			<-start // both requests fire together
			resp, err := cl.c.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}()
	}
	ready.Wait()
	close(start)
	wg.Wait()
	if !(codes[0] == http.StatusNoContent && codes[1] == http.StatusConflict) && !(codes[0] == http.StatusConflict && codes[1] == http.StatusNoContent) {
		t.Fatalf("codes %v", codes)
	}
	var n int
	if err := e.deps.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM role_bindings WHERE role = 'admin' AND subject_type = 'user' AND org_id IS NULL`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("admins left %d %v", n, err)
	}
}
