//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/config"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/meta"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/setup"
)

type testEnv struct {
	t      *testing.T
	srv    *httptest.Server
	deps   api.Deps
	client *http.Client
}

func newTestEnv(t *testing.T) *testEnv { return newTestEnvOpts(t) }

func newTestEnvOpts(t *testing.T, opts ...func(*api.Deps)) *testEnv {
	t.Helper()
	pool, q := dbtest.New(t)
	key := bytes.Repeat([]byte{7}, 32)
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(key), key))
	aud := audit.New(pool)
	sections := settings.DefaultRegistry()
	if err := authn.RegisterSettings(sections); err != nil {
		t.Fatal(err)
	}
	store := settings.NewStore(q, env)
	authSrc, err := authn.NewSettingsSource(store, sections)
	if err != nil {
		t.Fatal(err)
	}
	d := api.Deps{
		Config:       config.Config{BaseURL: "http://example.test"},
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Pool:         pool,
		Queries:      q,
		Settings:     store,
		Sections:     sections,
		Meta:         meta.NewRegistry(),
		Sessions:     authn.NewSessions(q, 12*time.Hour),
		Auditor:      aud,
		Setup:        setup.New(pool, aud, sections),
		AuthSettings: authSrc,
		LoginLimiter: authn.NewLimiter(0, 0),
	}
	for _, o := range opts {
		o(&d)
	}
	srv := httptest.NewServer(api.NewRouter(d))
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{t: t, srv: srv, deps: d, client: &http.Client{Jar: jar}}
}

// seedAdminSession creates a local admin with a global admin binding and an
// org, stores a session cookie in the client jar, and returns the CSRF token.
func (e *testEnv) seedAdminSession() (string, uuid.UUID) {
	e.t.Helper()
	ctx := context.Background()
	q := e.deps.Queries
	u, err := q.CreateLocalAdmin(ctx, "unused-hash")
	if err != nil {
		e.t.Fatal(err)
	}
	if err := q.CreateRoleBinding(ctx, sqlcgen.CreateRoleBindingParams{SubjectType: "user", Subject: u.ID.String(), Role: "admin"}); err != nil {
		e.t.Fatal(err)
	}
	org, err := q.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: "home", Name: "Home"})
	if err != nil {
		e.t.Fatal(err)
	}
	token, sess, err := e.deps.Sessions.Create(ctx, u.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	base, _ := url.Parse(e.srv.URL)
	e.client.Jar.SetCookies(base, []*http.Cookie{{Name: authn.CookieName, Value: token, Path: "/"}})
	return sess.Csrf, org.ID
}

func (e *testEnv) do(method, path string, body any, csrf string) (*http.Response, []byte) {
	e.t.Helper()
	if body == nil {
		return e.doRaw(method, path, "", "", csrf)
	}
	b, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.doRaw(method, path, "application/json", string(b), csrf)
}

// doWithCookie sends a request carrying cookieValue as the cf_session cookie
// directly, bypassing the client's cookie jar. The jar drops a cookie the
// server clears (MaxAge -1), so it cannot tell server-side session
// revocation apart from the client simply no longer holding the cookie.
func (e *testEnv) doWithCookie(method, path, cookieValue string) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: authn.CookieName, Value: cookieValue})
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, out
}

// doClient sends a request with client c and extra headers hdr.
func (e *testEnv) doClient(c *http.Client, method, path string, body any, hdr http.Header) (*http.Response, []byte) {
	e.t.Helper()
	var rdr io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, rdr)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, out
}

func (e *testEnv) doRaw(method, path, contentType, body, csrf string) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if csrf != "" {
		req.Header.Set(authn.CSRFHeader, csrf)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, out
}
