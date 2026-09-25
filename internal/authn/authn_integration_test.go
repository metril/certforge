//go:build integration

package authn_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// TestLoadPrincipalIgnoresSiteScopedBindings guards against privilege
// escalation: site scope is not modelled in Phase 1, so a role_bindings row
// with a non-NULL site_id must not be treated as an org-wide or global grant.
func TestLoadPrincipalIgnoresSiteScopedBindings(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	u, err := q.CreateLocalAdmin(ctx, "unused-hash")
	if err != nil {
		t.Fatal(err)
	}
	org, err := q.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: "home", Name: "Home"})
	if err != nil {
		t.Fatal(err)
	}
	var siteID uuid.UUID
	if err := pool.QueryRow(ctx, "INSERT INTO sites (org_id, name) VALUES ($1, $2) RETURNING id", org.ID, "Main").Scan(&siteID); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateRoleBinding(ctx, sqlcgen.CreateRoleBindingParams{
		SubjectType: "user", Subject: u.ID.String(), Role: "admin", OrgID: &org.ID, SiteID: &siteID,
	}); err != nil {
		t.Fatal(err)
	}
	p, err := authn.LoadPrincipal(ctx, q, u)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Roles) != 0 || len(p.Bindings) != 0 || len(p.OrgIDs) != 0 {
		t.Fatalf("principal %+v", p)
	}
}

func seedAdmin(t *testing.T, q *sqlcgen.Queries) sqlcgen.User {
	t.Helper()
	ctx := context.Background()
	u, err := q.CreateLocalAdmin(ctx, "unused-hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.CreateRoleBinding(ctx, sqlcgen.CreateRoleBindingParams{SubjectType: "user", Subject: u.ID.String(), Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	u := seedAdmin(t, q)
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	s := authn.NewSessions(q, time.Hour)
	s.SetClock(func() time.Time { return base })
	token, sess, err := s.Create(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID == token {
		t.Fatal("raw token stored as session id")
	}
	got, err := s.Lookup(ctx, token)
	if err != nil || got.Csrf != sess.Csrf {
		t.Fatalf("lookup %v err %v", got, err)
	}
	s.SetClock(func() time.Time { return base.Add(time.Hour + time.Second) })
	if _, err := s.Lookup(ctx, token); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("expired lookup err = %v", err)
	}
	if n, err := s.PurgeExpired(ctx); err != nil || n != 1 {
		t.Fatalf("purged %d err %v", n, err)
	}
	if _, err := s.Lookup(ctx, "bogus"); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("bogus err = %v", err)
	}
}

func TestLoadPrincipal(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	u := seedAdmin(t, q)
	org, err := q.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: "home", Name: "Home"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := authn.LoadPrincipal(ctx, q, u)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != authn.KindUser || len(p.Roles) != 1 || p.Roles[0] != "admin" {
		t.Fatalf("principal %+v", p)
	}
	if len(p.OrgIDs) != 1 || p.OrgIDs[0] != org.ID || p.Bindings[0].OrgID != nil {
		t.Fatalf("orgs %+v bindings %+v", p.OrgIDs, p.Bindings)
	}
}

func TestMiddleware(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	u := seedAdmin(t, q)
	current := time.Now()
	s := authn.NewSessions(q, time.Hour)
	s.SetClock(func() time.Time { return current })
	token, sess, err := s.Create(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	h := authn.Middleware(authn.MiddlewareOptions{
		Sessions: s,
		Queries:  q,
		Public:   func(r *http.Request) bool { return r.URL.Path == "/public" },
		Fail:     func(w http.ResponseWriter, status int, _, _ string) { w.WriteHeader(status) },
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := authn.PrincipalFrom(r.Context()); ok {
			_, _ = io.WriteString(w, p.Kind)
			return
		}
		_, _ = io.WriteString(w, "anon")
	}))
	call := func(method, path, cookie, csrf string) (int, string) {
		req := httptest.NewRequest(method, path, nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: authn.CookieName, Value: cookie})
		}
		if csrf != "" {
			req.Header.Set(authn.CSRFHeader, csrf)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	cases := []struct {
		name, method, path, cookie, csrf string
		code                             int
		body                             string
	}{
		{"no cookie private", http.MethodGet, "/private", "", "", 401, ""},
		{"no cookie public", http.MethodGet, "/public", "", "", 200, "anon"},
		{"bogus cookie private", http.MethodGet, "/private", "bogus", "", 401, ""},
		{"valid GET", http.MethodGet, "/private", token, "", 200, "user"},
		{"POST without CSRF", http.MethodPost, "/private", token, "", 403, ""},
		{"PUT without CSRF", http.MethodPut, "/private", token, "", 403, ""},
		{"POST wrong CSRF", http.MethodPost, "/private", token, "nope", 403, ""},
		{"POST right CSRF", http.MethodPost, "/private", token, sess.Csrf, 200, "user"},
		{"DELETE right CSRF", http.MethodDelete, "/private", token, sess.Csrf, 200, "user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := call(tc.method, tc.path, tc.cookie, tc.csrf)
			if code != tc.code || (tc.body != "" && body != tc.body) {
				t.Fatalf("got %d %q, want %d %q", code, body, tc.code, tc.body)
			}
		})
	}
	t.Run("expired session", func(t *testing.T) {
		saved := current
		current = current.Add(time.Hour + time.Second)
		defer func() { current = saved }()
		if code, _ := call(http.MethodGet, "/private", token, ""); code != 401 {
			t.Fatalf("private code %d", code)
		}
		if code, body := call(http.MethodGet, "/public", token, ""); code != 200 || body != "anon" {
			t.Fatalf("public %d %q", code, body)
		}
	})
	t.Run("disabled user", func(t *testing.T) {
		if err := q.SetUserDisabled(ctx, sqlcgen.SetUserDisabledParams{ID: u.ID, Disabled: true}); err != nil {
			t.Fatal(err)
		}
		if code, _ := call(http.MethodGet, "/private", token, ""); code != 401 {
			t.Fatalf("code %d", code)
		}
	})
}

func TestLoadPrincipalGroupBindings(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	org := dbtest.Org(t, pool)
	u, err := q.UpsertOIDCUser(ctx, sqlcgen.UpsertOIDCUserParams{Issuer: "https://idp.test", Subject: "s1", DisplayName: "Ann", Groups: []string{"ops"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"ops", "other"} {
		if err := q.CreateRoleBinding(ctx, sqlcgen.CreateRoleBindingParams{SubjectType: "oidc_group", Subject: g, Role: "operator", OrgID: &org}); err != nil {
			t.Fatal(err)
		}
	}
	p, err := authn.LoadPrincipal(ctx, q, u)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Bindings) != 1 || p.Bindings[0].Role != "operator" || len(p.OrgIDs) != 1 || p.OrgIDs[0] != org {
		t.Fatalf("principal %+v", p)
	}

	if err := q.CreateRoleBinding(ctx, sqlcgen.CreateRoleBindingParams{SubjectType: "oidc_group", Subject: "OPS", Role: "viewer", OrgID: &org}); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateRoleBinding(ctx, sqlcgen.CreateRoleBindingParams{SubjectType: "oidc_group", Subject: "ops", Role: "auditor"}); err != nil {
		t.Fatal(err)
	}
	p, err = authn.LoadPrincipal(ctx, q, u)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(p.Bindings, func(b authn.Binding) bool { return b.Role == "viewer" }) {
		t.Fatalf("group binding matched case-insensitively: %+v", p.Bindings)
	}
	if !slices.ContainsFunc(p.Bindings, func(b authn.Binding) bool { return b.Role == "auditor" && b.OrgID == nil }) {
		t.Fatalf("missing global (org-less) group binding: %+v", p.Bindings)
	}
}
