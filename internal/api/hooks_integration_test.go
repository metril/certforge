//go:build integration

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/deploy"
)

// checkJobs records GrantCheckArgs inserts (and ignores deploy jobs).
type checkJobs struct {
	mu  sync.Mutex
	ids []uuid.UUID
}

func (j *checkJobs) InsertTx(_ context.Context, _ pgx.Tx, a river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	if c, ok := a.(deploy.GrantCheckArgs); ok {
		j.mu.Lock()
		j.ids = append(j.ids, c.MonitorID)
		j.mu.Unlock()
	}
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}}, nil
}

func (j *checkJobs) count() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.ids)
}

type hookEnv struct {
	f      *agentFixture
	jobs   *checkJobs
	h      http.Handler
	op     context.Context
	target uuid.UUID
}

func newHookEnv(t *testing.T) *hookEnv {
	t.Helper()
	f := newAgentFixture(t)
	jobs := &checkJobs{}
	f.srv.d.Dispatcher.River = jobs
	f.srv.d.HookIPLimiter = authn.NewLimiter(hookIPPerMinute, hookIPBurst)
	f.srv.d.HookGrantLimiter = authn.NewLimiter(hookGrantPerMinute, hookGrantBurst)
	r := chi.NewRouter()
	r.With(withClientIP(nil)).Post("/hooks/v1/grants/{grantId}/check", f.srv.checkHook)
	target, _ := f.serverTarget(t, "vault", nil)
	return &hookEnv{f: f, jobs: jobs, h: r, op: f.as("operator"), target: target}
}

// grant creates a server grant, with a verify endpoint when verify is set.
func (e *hookEnv) grant(t *testing.T, name string, verify bool) uuid.UUID {
	t.Helper()
	certID, _ := e.f.currentCert(t, name)
	in := &gen.ServerGrantInput{CertificateId: certID}
	if verify {
		in.Verify = &gen.GrantVerify{Host: name + ".example.test", Port: 443}
	}
	res, err := e.f.srv.CreateServerGrant(e.op, gen.CreateServerGrantRequestObject{OrgId: e.f.org, Id: e.target, Body: in})
	if err != nil {
		t.Fatal(err)
	}
	return res.(gen.CreateServerGrant201JSONResponse).Id
}

func (e *hookEnv) token(t *testing.T, grant uuid.UUID) string {
	t.Helper()
	res, err := e.f.srv.CreateGrantCheckToken(e.op, gen.CreateGrantCheckTokenRequestObject{OrgId: e.f.org, Id: grant})
	if err != nil {
		t.Fatal(err)
	}
	return res.(gen.CreateGrantCheckToken201JSONResponse).Token
}

func (e *hookEnv) call(grant uuid.UUID, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/hooks/v1/grants/"+grant.String()+"/check", nil)
	req.RemoteAddr = "192.0.2.7:1234"
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

func TestCheckHook(t *testing.T) {
	e := newHookEnv(t)
	g := e.grant(t, "web", true)
	other := e.grant(t, "api", true)
	tok := e.token(t, g)

	if w := e.call(g, "Bearer "+tok); w.Code != 202 || w.Body.String() != "{\"queued\":true}\n" || e.jobs.count() != 1 {
		t.Fatalf("valid: %d %q jobs=%d", w.Code, w.Body.String(), e.jobs.count())
	}
	for name, c := range map[string]struct {
		grant uuid.UUID
		auth  string
	}{
		"no header":    {g, ""},
		"malformed":    {g, "Bearer nope"},
		"not bearer":   {g, tok},
		"wrong secret": {g, "Bearer " + tok[:len(tok)-3] + "AAA"},
		"wrong grant":  {other, "Bearer " + tok},
	} {
		if w := e.call(c.grant, c.auth); w.Code != 404 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if e.jobs.count() != 1 {
		t.Fatalf("failures enqueued: %d", e.jobs.count())
	}

	// Rotation kills the old token.
	tok2 := e.token(t, g)
	if w := e.call(g, "Bearer "+tok); w.Code != 404 {
		t.Fatalf("rotated old token: %d", w.Code)
	}
	if w := e.call(g, "Bearer "+tok2); w.Code != 202 {
		t.Fatalf("rotated new token: %d", w.Code)
	}

	// Revoke.
	if _, err := e.f.srv.DeleteGrantCheckToken(e.op, gen.DeleteGrantCheckTokenRequestObject{OrgId: e.f.org, Id: g}); err != nil {
		t.Fatal(err)
	}
	if w := e.call(g, "Bearer "+tok2); w.Code != 404 {
		t.Fatalf("revoked: %d", w.Code)
	}
}

func TestCheckHookNoMonitorConflict(t *testing.T) {
	e := newHookEnv(t)
	g := e.grant(t, "bare", false)
	_, err := e.f.srv.CreateGrantCheckToken(e.op, gen.CreateGrantCheckTokenRequestObject{OrgId: e.f.org, Id: g})
	if he, ok := err.(*HTTPError); !ok || he.Status != http.StatusConflict {
		t.Fatalf("err = %v", err)
	}
}

// A monitor removed after the token was issued still answers 202, no job.
func TestCheckHookMonitorGone(t *testing.T) {
	e := newHookEnv(t)
	g := e.grant(t, "web", true)
	tok := e.token(t, g)
	if _, err := e.f.pool.Exec(context.Background(), "DELETE FROM external_monitors WHERE grant_id = $1", g); err != nil {
		t.Fatal(err)
	}
	if w := e.call(g, "Bearer "+tok); w.Code != 202 || e.jobs.count() != 0 {
		t.Fatalf("%d jobs=%d", w.Code, e.jobs.count())
	}
}

func TestCheckHookRateLimit(t *testing.T) {
	e := newHookEnv(t)
	g := e.grant(t, "web", true)
	tok := e.token(t, g)
	codes := map[int]int{}
	var retry string
	for i := 0; i < hookGrantBurst+2; i++ {
		w := e.call(g, "Bearer "+tok)
		codes[w.Code]++
		if w.Code == 429 {
			retry = w.Header().Get("Retry-After")
		}
	}
	if codes[202] != hookGrantBurst || codes[429] != 2 || retry == "" {
		t.Fatalf("codes=%v retry=%q", codes, retry)
	}
	// The per-IP limit applies even to unauthenticated noise.
	e2 := newHookEnv(t)
	n := 0
	for i := 0; i < hookIPBurst+3; i++ {
		if w := e2.call(uuid.New(), "Bearer x"); w.Code == 429 {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("ip 429s = %d", n)
	}
}

func TestCheckTokenAuthz(t *testing.T) {
	e := newHookEnv(t)
	g := e.grant(t, "web", true)
	v := e.f.as("viewer")
	if _, err := e.f.srv.CreateGrantCheckToken(v, gen.CreateGrantCheckTokenRequestObject{OrgId: e.f.org, Id: g}); err == nil {
		t.Fatal("viewer create allowed")
	}
	if _, err := e.f.srv.DeleteGrantCheckToken(v, gen.DeleteGrantCheckTokenRequestObject{OrgId: e.f.org, Id: g}); err == nil {
		t.Fatal("viewer delete allowed")
	}
	set := func() bool {
		out, err := e.f.srv.serverGrantByID(context.Background(), e.f.org, g)
		if err != nil {
			t.Fatal(err)
		}
		return out.CheckTokenSet != nil && *out.CheckTokenSet
	}
	if set() {
		t.Fatal("token set before generate")
	}
	e.token(t, g)
	if !set() {
		t.Fatal("checkTokenSet false after generate")
	}
}
