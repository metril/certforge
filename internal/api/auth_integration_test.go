//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

type meBody struct {
	User struct {
		DisplayName string `json:"displayName"`
		LocalAdmin  bool   `json:"localAdmin"`
	} `json:"user"`
	Roles     []string                `json:"roles"`
	Orgs      []struct{ Slug string } `json:"orgs"`
	CsrfToken string                  `json:"csrfToken"`
}

func seedAdminPassword(t *testing.T, e *testEnv, pw string) {
	t.Helper()
	ctx := context.Background()
	hash, err := authn.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.deps.Queries.CreateLocalAdmin(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.deps.Queries.CreateRoleBinding(ctx, sqlcgen.CreateRoleBindingParams{SubjectType: "user", Subject: u.ID.String(), Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.deps.Queries.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: "home", Name: "Home"}); err != nil {
		t.Fatal(err)
	}
}

func TestLoginMeLogout(t *testing.T) {
	e := newTestEnv(t)
	seedAdminPassword(t, e, "correct horse battery")

	resp, _ := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": "wrong password!"}, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password code %d", resp.StatusCode)
	}
	resp, body := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": "correct horse battery"}, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %d %s", resp.StatusCode, body)
	}
	var c *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == authn.CookieName {
			c = ck
		}
	}
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure {
		t.Fatalf("cookie %+v", c)
	}
	var me meBody
	if err := json.Unmarshal(body, &me); err != nil || me.CsrfToken == "" || !me.User.LocalAdmin ||
		len(me.Roles) != 1 || me.Roles[0] != "admin" || len(me.Orgs) != 1 {
		t.Fatalf("me %s", body)
	}

	resp, body = e.do(http.MethodGet, "/api/v1/auth/me", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me %d %s", resp.StatusCode, body)
	}
	if resp, _ = e.do(http.MethodPost, "/api/v1/auth/logout", nil, ""); resp.StatusCode != http.StatusForbidden { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("logout without csrf %d", resp.StatusCode)
	}
	if resp, _ = e.do(http.MethodPost, "/api/v1/auth/logout", nil, me.CsrfToken); resp.StatusCode != http.StatusNoContent { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("logout %d", resp.StatusCode)
	}
	// The client's cookie jar drops the cleared cookie, so it can't tell
	// server-side revocation apart from just not holding a cookie anymore.
	// Resend the pre-logout cookie value explicitly to prove the session
	// itself was deleted, not just the cookie cleared.
	if resp, _ = e.doWithCookie(http.MethodGet, "/api/v1/auth/me", c.Value); resp.StatusCode != http.StatusUnauthorized { //nolint:bodyclose // testEnv.doWithCookie closes the body
		t.Fatalf("me with revoked session cookie %d", resp.StatusCode)
	}
}

func TestLoginNoAdmin(t *testing.T) {
	e := newTestEnv(t)
	resp, _ := e.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"password": "anything at all"}, "") //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("code %d", resp.StatusCode)
	}
}
