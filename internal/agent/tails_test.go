//go:build unix

package agent

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
)

type tailEnv struct {
	r        *Reconciler
	dir      string
	script   string
	log      string
	restarts *atomic.Int32
	status   *atomic.Int32 // docker reply status
	api      *fakeAPI
}

func newTailEnv(t *testing.T) *tailEnv {
	t.Helper()
	dir := t.TempDir()
	e := &tailEnv{dir: dir, restarts: &atomic.Int32{}, status: &atomic.Int32{}, log: filepath.Join(dir, "runs.log")}
	e.status.Store(204)
	sock := dockerStub(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/restart") { // the runner also probes the API version
			w.WriteHeader(404)
			return
		}
		e.restarts.Add(1)
		w.WriteHeader(int(e.status.Load()))
	})
	e.script = filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(e.script, []byte("#!/bin/sh\necho \"$CF_GRANT_ID $1\" >> "+e.log+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	d := testDeployer([]string{dir}, e.script)
	d.Restart = &RestartRunner{Allow: map[string]bool{"docker:nginx": true}, DockerAddr: sock}
	e.api = &fakeAPI{bundles: map[uuid.UUID]agentproto.Bundle{}}
	e.r = &Reconciler{API: e.api, Deployer: d, ID: newTestIdentity(t), Log: discard}
	return e
}

func (e *tailEnv) grant(name string, hooks ...agentproto.HookSpec) agentproto.Assignment {
	a, b := layoutGrant(e.dir, name)
	a.Hooks = hooks
	e.api.as.Grants = append(e.api.as.Grants, a)
	e.api.bundles[a.ID] = b
	return a
}

func (e *tailEnv) logged() []string {
	b, _ := os.ReadFile(e.log)
	return strings.Fields(strings.ReplaceAll(string(b), "\n", " "))
}

func execHook(e *tailEnv, tag string, once bool) agentproto.HookSpec {
	return agentproto.HookSpec{ID: uuid.New(), Phase: "post_deploy", Kind: "exec", Argv: []string{e.script, tag}, TimeoutSeconds: 5, OncePerHost: once}
}

func TestReconcileRestartsOncePerRun(t *testing.T) {
	e := newTailEnv(t)
	a1 := e.grant("a", restartSpec("docker:nginx"))
	a2 := e.grant("b", restartSpec("docker:nginx"))
	rep, err := e.r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if e.restarts.Load() != 1 {
		t.Fatalf("restarts = %d", e.restarts.Load())
	}
	for _, res := range rep.Results {
		if res.State != agentproto.StateOK || len(res.HookRuns) != 1 || res.HookRuns[0].ExitCode != 0 {
			t.Fatalf("result %+v", res)
		}
	}
	for _, a := range []agentproto.Assignment{a1, a2} {
		if _, ok := e.r.ID.State.Grants[a.ID]; !ok {
			t.Fatalf("grant %s not recorded", a.ID)
		}
	}
}

func TestReconcileTailKeepsPerGrantHooksAroundSharedRestart(t *testing.T) {
	e := newTailEnv(t)
	e.grant("a", execHook(e, "pre", false), restartSpec("docker:nginx"), execHook(e, "post", false))
	e.grant("b", execHook(e, "pre", false), restartSpec("docker:nginx"), execHook(e, "post", false))
	rep, err := e.r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if e.restarts.Load() != 1 {
		t.Fatalf("restarts = %d", e.restarts.Load())
	}
	got := e.logged() // pairs: grant, tag
	var pre, post int
	for i := 1; i < len(got); i += 2 {
		switch got[i] {
		case "pre":
			pre++
		case "post":
			post++
		}
	}
	if pre != 2 || post != 2 || len(got) != 8 {
		t.Fatalf("log = %v", got)
	}
	for _, res := range rep.Results {
		if res.State != agentproto.StateOK || len(res.HookRuns) != 3 {
			t.Fatalf("result %+v", res)
		}
	}
}

func TestReconcileRestartFailureLeavesGrantsPending(t *testing.T) {
	e := newTailEnv(t)
	a1 := e.grant("a")
	a2 := e.grant("b")
	if _, err := e.r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Redeploy both with a restart that fails, and a later per-grant hook.
	for i := range e.api.as.Grants {
		e.api.as.Grants[i].RedeploySeq++
		e.api.as.Grants[i].Hooks = []agentproto.HookSpec{restartSpec("docker:nginx"), execHook(e, "after", false)}
	}
	e.status.Store(500)
	rep, err := e.r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if e.restarts.Load() != 1 {
		t.Fatalf("restarts = %d", e.restarts.Load())
	}
	for _, res := range rep.Results {
		if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "restart docker:nginx") || len(res.HookRuns) != 1 {
			t.Fatalf("result %+v", res)
		}
	}
	if len(e.logged()) != 0 {
		t.Fatalf("later hooks ran: %v", e.logged())
	}
	for _, a := range []agentproto.Assignment{a1, a2} {
		if !e.r.ID.State.Grants[a.ID].Pending {
			t.Fatalf("grant %s not pending", a.ID)
		}
	}
	// The next run retries and succeeds.
	e.status.Store(204)
	rep, err = e.r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range rep.Results {
		if res.State != agentproto.StateOK {
			t.Fatalf("retry %+v", res)
		}
	}
	if e.restarts.Load() != 2 || len(e.logged()) != 4 {
		t.Fatalf("restarts %d log %v", e.restarts.Load(), e.logged())
	}
}

func TestReconcileExecOncePerHostOptIn(t *testing.T) {
	e := newTailEnv(t)
	a1 := e.grant("a", execHook(e, "once", true))
	a2 := e.grant("b", execHook(e, "once", true))
	// Same action on both grants: one run, with the lower grant id's env.
	e.api.as.Grants[1].Hooks[0].ID = e.api.as.Grants[0].Hooks[0].ID
	if _, err := e.r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := a1.ID
	if strings.Compare(a2.ID.String(), a1.ID.String()) < 0 {
		first = a2.ID
	}
	if got := e.logged(); len(got) != 2 || got[0] != first.String() {
		t.Fatalf("log = %v, want one run for %s", got, first)
	}
}

func TestReconcileExecWithoutOptInRunsPerGrant(t *testing.T) {
	e := newTailEnv(t)
	h := execHook(e, "x", false)
	e.grant("a", h)
	e.grant("b", h)
	if _, err := e.r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := e.logged(); len(got) != 4 {
		t.Fatalf("log = %v", got)
	}
}
