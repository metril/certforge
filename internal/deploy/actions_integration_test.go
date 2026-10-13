//go:build integration

package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/actions"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx/sshxtest"
	"github.com/metril/certforge/internal/targets/targetstest"
)

// sshTarget stores an ssh deploy target pointing at s (password sealed).
func (f *dispatcherFixture) sshTarget(t *testing.T, s *sshxtest.Server, port int) uuid.UUID {
	t.Helper()
	pub, _ := json.Marshal(map[string]any{"host": "127.0.0.1", "port": port, "username": "root", "hostKey": s.HostLine(),
		"files": []any{}, "timeoutSeconds": 10})
	s.Pass = "s3cret"
	sealed, err := f.box.Seal(context.Background(), []byte(`{"password":"s3cret"}`))
	if err != nil {
		t.Fatal(err)
	}
	dt, err := f.q.CreateDeployTarget(context.Background(), sqlcgen.CreateDeployTargetParams{
		OrgID: f.org, Name: "ssh-" + uuid.NewString()[:8], Type: "ssh", RunsOn: "server", Config: pub, SecretCfg: sealed})
	if err != nil {
		t.Fatal(err)
	}
	return dt.ID
}

// actionOpts tunes f.action.
type actionOpts struct {
	optional bool
	timeout  int
	secrets  map[string]string
}

// action stores an org action and returns its id.
func (f *dispatcherFixture) action(t *testing.T, name, kind, phase string, cfg any, o ...actionOpts) uuid.UUID {
	t.Helper()
	var op actionOpts
	if len(o) > 0 {
		op = o[0]
	}
	if op.timeout == 0 {
		op.timeout = 10
	}
	raw, _ := json.Marshal(cfg)
	var sealed []byte
	if len(op.secrets) > 0 {
		sb, _ := json.Marshal(op.secrets)
		var err error
		if sealed, err = f.box.Seal(context.Background(), sb); err != nil {
			t.Fatal(err)
		}
	}
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO actions (org_id, name, kind, phase, config, secret_cfg, timeout_seconds, optional)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`, f.org, name, kind, phase, raw, sealed, op.timeout, op.optional).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *dispatcherFixture) group(t *testing.T, name string, ids ...uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO action_groups (org_id, name, action_ids) VALUES ($1, $2, $3) RETURNING id`, f.org, name, ids).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// setSteps stores the grant's steps: an action id is {"action"}, an id in
// groups is {"group"}.
func (f *dispatcherFixture) setSteps(t *testing.T, grantID uuid.UUID, steps ...any) {
	t.Helper()
	b, _ := json.Marshal(steps)
	if _, err := f.pool.Exec(context.Background(), `UPDATE client_cert_grants SET steps = $2 WHERE id = $1`, grantID, b); err != nil {
		t.Fatal(err)
	}
}

func step(id uuid.UUID) map[string]uuid.UUID  { return map[string]uuid.UUID{"action": id} }
func gstep(id uuid.UUID) map[string]uuid.UUID { return map[string]uuid.UUID{"group": id} }

func (f *dispatcherFixture) row(t *testing.T, grantID uuid.UUID) sqlcgen.ServerDeployGrantRow {
	t.Helper()
	row, err := f.q.ServerDeployGrant(context.Background(), grantID)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// stepOf loads an action as the dispatcher would.
func (f *dispatcherFixture) stepOf(t *testing.T, id uuid.UUID) stepAction {
	t.Helper()
	rows, err := f.q.ServerActionsByIDs(context.Background(), sqlcgen.ServerActionsByIDsParams{Ids: []uuid.UUID{id}, OrgID: f.org})
	if err != nil || len(rows) != 1 {
		t.Fatal(err, len(rows))
	}
	r := rows[0]
	return stepAction{Name: r.Name, Sealed: r.SecretCfg, ActionRef: actions.ActionRef{ID: r.ID, Kind: r.Kind, Phase: r.Phase,
		RunsOn: targets.Server, Optional: r.Optional, TimeoutSeconds: int(r.TimeoutSeconds), Config: r.Config}}
}

type recordedRun struct {
	phase, stdout, stderr string
	argv                  []string
	exit                  int
	client                *uuid.UUID
	target                *uuid.UUID
	action                *uuid.UUID
}

func (f *dispatcherFixture) runs(t *testing.T, grantID uuid.UUID) []recordedRun {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT phase, argv, exit_code, stdout, stderr, client_id, deploy_target_id, hook_id FROM hook_runs WHERE grant_id = $1 ORDER BY ran_at, id`, grantID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []recordedRun
	for rows.Next() {
		var r recordedRun
		if err := rows.Scan(&r.phase, &r.argv, &r.exit, &r.stdout, &r.stderr, &r.client, &r.target, &r.action); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// stepSetup is a grant on a recording fake target with one ssh target.
type stepSetup struct {
	f      *dispatcherFixture
	g, ver uuid.UUID
	target uuid.UUID
	sec    *targetstest.Secret
	ssh    uuid.UUID
	srv    *sshxtest.Server
}

func newStepSetup(t *testing.T) *stepSetup {
	t.Helper()
	s := sshxtest.Start(t, nil)
	f := newDispatcherFixture(t)
	target, sec := f.target(t, "plain", targets.Server, targets.Never, map[string]any{"url": "https://x.example.test", "token": "tok"})
	ssh := f.sshTarget(t, s, s.Port(t))
	cert := f.cert(t, "web")
	ver := f.version(t, cert, "1", false)
	g := f.grant(t, cert, target)
	f.pending(t, g, ver)
	return &stepSetup{f: f, g: g, ver: ver, target: target, sec: sec, ssh: ssh, srv: s}
}

func (u *stepSetup) sshAction(t *testing.T, name, phase, cmd string, o ...actionOpts) uuid.UUID {
	t.Helper()
	return u.f.action(t, name, "ssh", phase, map[string]any{"targetId": u.ssh, "command": cmd}, o...)
}

func TestActionSSHPostRecorded(t *testing.T) {
	u := newStepSetup(t)
	a := u.sshAction(t, "reload", "post_deploy", "systemctl reload nginx")
	u.f.setSteps(t, u.g, step(a))
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err != nil {
		t.Fatal(err)
	}
	if st := u.f.status(t, u.g); st != "deployed" {
		t.Fatalf("status = %s", st)
	}
	if len(u.srv.Cmds) != 1 || u.srv.Cmds[0] != "systemctl reload nginx" {
		t.Fatalf("cmds = %q", u.srv.Cmds)
	}
	runs := u.f.runs(t, u.g)
	if len(runs) != 1 || runs[0].phase != "post_deploy" || runs[0].exit != 0 || runs[0].client != nil ||
		runs[0].target == nil || *runs[0].target != u.target || runs[0].action == nil || *runs[0].action != a ||
		strings.Join(runs[0].argv, "|") != "ssh|127.0.0.1|systemctl reload nginx" {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestActionNonZeroFailsDeployment(t *testing.T) {
	u := newStepSetup(t)
	u.srv.Exit = 3
	u.f.setSteps(t, u.g, step(u.sshAction(t, "reload", "post_deploy", "false")))
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err == nil {
		t.Fatal("expected error")
	}
	if st := u.f.status(t, u.g); st != "failed" {
		t.Fatalf("status = %s", st)
	}
	if le := u.f.lastError(t, u.g); !strings.Contains(le, "deployed, but post action reload failed: exit 3") || strings.Contains(le, "s3cret") {
		t.Fatalf("last_error = %q", le)
	}
	if runs := u.f.runs(t, u.g); len(runs) != 1 || runs[0].exit != 3 {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestActionDialFailureRecorded(t *testing.T) {
	u := newStepSetup(t)
	u.f.setSteps(t, u.g, step(u.sshAction(t, "reload", "post_deploy", "true")))
	if _, err := u.f.pool.Exec(context.Background(), `UPDATE deploy_targets SET config = jsonb_set(config, '{port}', '1') WHERE type = 'ssh'`); err != nil {
		t.Fatal(err)
	}
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err == nil {
		t.Fatal("expected error")
	}
	if st := u.f.status(t, u.g); st != "failed" {
		t.Fatalf("status = %s", st)
	}
	if runs := u.f.runs(t, u.g); len(runs) != 1 || runs[0].exit != -1 || runs[0].stderr == "" {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestActionOnPiKVMTarget(t *testing.T) {
	u := newStepSetup(t)
	u.f.setSteps(t, u.g, step(u.sshAction(t, "hi", "post_deploy", "echo hi")))
	if _, err := u.f.pool.Exec(context.Background(), `UPDATE deploy_targets SET type = 'pikvm' WHERE type = 'ssh'`); err != nil {
		t.Fatal(err)
	}
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err != nil {
		t.Fatal(err)
	}
	if len(u.srv.Cmds) != 1 || u.srv.Cmds[0] != "echo hi" {
		t.Fatalf("cmds = %q", u.srv.Cmds)
	}
}

func TestPreActionFailureDeploysNothing(t *testing.T) {
	u := newStepSetup(t)
	u.srv.Exit = 2
	u.f.setSteps(t, u.g, step(u.sshAction(t, "drain", "pre_deploy", "drain")))
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err == nil {
		t.Fatal("expected error")
	}
	if len(u.sec.Calls) != 0 {
		t.Fatalf("target was deployed to %d times", len(u.sec.Calls))
	}
	if le := u.f.lastError(t, u.g); !strings.Contains(le, "pre action drain failed; not deployed: exit 2") {
		t.Fatalf("last_error = %q", le)
	}
	if runs := u.f.runs(t, u.g); len(runs) != 1 || runs[0].phase != "pre_deploy" {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestOptionalPostFailureStillDeploys(t *testing.T) {
	u := newStepSetup(t)
	u.srv.Exit = 1
	u.f.setSteps(t, u.g, step(u.sshAction(t, "nice", "post_deploy", "maybe", actionOpts{optional: true})))
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err != nil {
		t.Fatal(err)
	}
	if st := u.f.status(t, u.g); st != "deployed" {
		t.Fatalf("status = %s", st)
	}
	if runs := u.f.runs(t, u.g); len(runs) != 1 || runs[0].exit != 1 {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestActionGroupOrderAndPhases(t *testing.T) {
	u := newStepSetup(t)
	a := u.sshAction(t, "a", "post_deploy", "A")
	b := u.sshAction(t, "b", "post_deploy", "B")
	c := u.sshAction(t, "c", "post_deploy", "C")
	d := u.sshAction(t, "d", "post_deploy", "D")
	pre := u.sshAction(t, "pre", "pre_deploy", "PRE")
	grp := u.f.group(t, "bc", b, c)
	u.f.setSteps(t, u.g, step(a), gstep(grp), step(d), step(pre))
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(u.srv.Cmds, ","); got != "PRE,A,B,C,D" {
		t.Fatalf("cmds = %s", got)
	}
}

func TestActionHTTPPost(t *testing.T) {
	u := newStepSetup(t)
	var gotAuth, gotBody, gotHdr, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotAuth, gotBody, gotHdr, gotMethod = r.Header.Get("Authorization"), string(b), r.Header.Get("X-Env"), r.Method
		w.WriteHeader(201)
		_, _ = io.WriteString(w, "created")
	}))
	defer srv.Close()
	sh, _ := json.Marshal(map[string]string{"Authorization": "Bearer tok-s3cret"})
	a := u.f.action(t, "hook", "http", "post_deploy", map[string]any{"method": "POST", "url": srv.URL + "/x?k=v", "headers": map[string]string{"X-Env": "prod"},
		"body": "cert={{cert.name}} grant={{grant.id}}", "expectedStatus": map[string]int{"min": 201, "max": 201}},
		actionOpts{secrets: map[string]string{"secretHeaders": string(sh)}})
	u.f.setSteps(t, u.g, step(a))
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err != nil {
		t.Fatal(err)
	}
	if gotMethod != "POST" || gotAuth != "Bearer tok-s3cret" || gotHdr != "prod" || gotBody != "cert=web grant="+u.g.String() {
		t.Fatalf("got %s %q %q %q", gotMethod, gotAuth, gotHdr, gotBody)
	}
	runs := u.f.runs(t, u.g)
	if len(runs) != 1 || runs[0].exit != 201 || runs[0].stdout != "created" || strings.Contains(strings.Join(runs[0].argv, " "), "k=v") {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestActionHTTPBadStatusRedacted(t *testing.T) {
	u := newStepSetup(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = io.WriteString(w, "echo "+r.Header.Get("Authorization"))
	}))
	defer srv.Close()
	sh, _ := json.Marshal(map[string]string{"Authorization": "tok-s3cret"})
	a := u.f.action(t, "hook", "http", "post_deploy", map[string]any{"method": "GET", "url": srv.URL},
		actionOpts{secrets: map[string]string{"secretHeaders": string(sh)}})
	u.f.setSteps(t, u.g, step(a))
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err == nil {
		t.Fatal("expected error")
	}
	le := u.f.lastError(t, u.g)
	if !strings.Contains(le, "status 500") || strings.Contains(le, "tok-s3cret") {
		t.Fatalf("last_error = %q", le)
	}
	for _, r := range u.f.runs(t, u.g) {
		if strings.Contains(r.stdout+r.stderr, "tok-s3cret") {
			t.Fatalf("secret recorded: %+v", r)
		}
	}
}

func TestActionVerifyTLS(t *testing.T) {
	u := newStepSetup(t)
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	a := u.f.action(t, "tls", "verify_tls", "post_deploy", map[string]any{"host": "127.0.0.1", "port": p})
	row := u.f.row(t, u.g)
	req := targets.Request{HTTP: targets.HTTPFactory{AllowLoopback: true}, Fingerprint: agentproto.CertFingerprint(srv.Certificate().Raw)}
	if err := u.f.disp.runAction(context.Background(), row, u.f.stepOf(t, a), req); err != nil {
		t.Fatal(err)
	}
	req.Fingerprint = strings.Repeat("0", 64)
	if err := u.f.disp.runAction(context.Background(), row, u.f.stepOf(t, a), req); err == nil || !strings.Contains(err.Error(), "not the deployed") {
		t.Fatalf("err = %v", err)
	}
	req.HTTP.AllowLoopback = false
	if err := u.f.disp.runAction(context.Background(), row, u.f.stepOf(t, a), req); err == nil {
		t.Fatal("loopback allowed")
	}
	if runs := u.f.runs(t, u.g); len(runs) != 3 || runs[0].exit != 0 || runs[1].exit != -1 {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestActionWait(t *testing.T) {
	u := newStepSetup(t)
	a := u.f.action(t, "pause", "wait", "post_deploy", map[string]any{"seconds": 1})
	row := u.f.row(t, u.g)
	start := time.Now()
	if err := u.f.disp.runAction(context.Background(), row, u.f.stepOf(t, a), targets.Request{}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < time.Second {
		t.Fatal("did not wait")
	}
	long := u.f.action(t, "long", "wait", "post_deploy", map[string]any{"seconds": 300})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := u.f.disp.runAction(ctx, row, u.f.stepOf(t, long), targets.Request{}); err == nil {
		t.Fatal("wait ignored the context")
	}
}

type fakeNotifier struct {
	calls []DeployNotice
	err   error
}

func (n *fakeNotifier) SendDeploy(_ context.Context, _, _ uuid.UUID, d DeployNotice) error {
	n.calls = append(n.calls, d)
	return n.err
}

func TestActionNotify(t *testing.T) {
	u := newStepSetup(t)
	fn := &fakeNotifier{}
	u.f.disp.Notify = fn
	ch := uuid.New()
	u.f.setSteps(t, u.g, step(u.f.action(t, "tell", "notify", "post_deploy", map[string]any{"channelId": ch})))
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err != nil {
		t.Fatal(err)
	}
	if len(fn.calls) != 1 || fn.calls[0].GrantID != u.g || fn.calls[0].CertName != "web" || fn.calls[0].Phase != "post_deploy" {
		t.Fatalf("calls = %+v", fn.calls)
	}
	// A failing channel fails the deploy; a missing notifier does too.
	u.f.pending(t, u.g, u.ver)
	fn.err = errors.New("channel down")
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err == nil || !strings.Contains(err.Error(), "channel down") {
		t.Fatalf("err = %v", err)
	}
	u.f.pending(t, u.g, u.ver)
	u.f.disp.Notify = nil
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("err = %v", err)
	}
}

func TestAgentActionRejectedOnServerGrant(t *testing.T) {
	u := newStepSetup(t)
	a := u.f.action(t, "x", "exec", "post_deploy", map[string]any{"argv": []string{"/bin/true"}})
	u.f.setSteps(t, u.g, step(a))
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err == nil || !strings.Contains(err.Error(), "runs on an agent") {
		t.Fatalf("err = %v", err)
	}
	if len(u.sec.Calls) != 0 {
		t.Fatal("deployed")
	}
}

// pfSenseStepTarget makes the grant's own target a pfsense target backed by fake.
func (u *stepSetup) pfSenseTarget(t *testing.T, fake *httptest.Server) {
	t.Helper()
	cfg, _ := json.Marshal(map[string]any{"url": fake.URL + "/api", "username": "admin", "timeoutSeconds": 5})
	sealed, _ := u.f.box.Seal(context.Background(), []byte(`{"password":"`+pfPass+`"}`))
	if _, err := u.f.pool.Exec(context.Background(), `UPDATE deploy_targets SET type = 'pfsense', config = $2, secret_cfg = $3 WHERE id = $1`, u.target, cfg, sealed); err != nil {
		t.Fatal(err)
	}
}

func TestActionPfSenseRestart(t *testing.T) {
	u := newStepSetup(t)
	f := &fakePF{list: `[{"refid":"abc","descr":"web"}]`, phpOut: pfPHPOut}
	srv := httptest.NewServer(f)
	defer srv.Close()
	u.pfSenseTarget(t, srv)
	row := u.f.row(t, u.g)
	req := targets.Request{CertName: "web", HTTP: targets.HTTPFactory{AllowLoopback: true}}
	run := func(cfg map[string]any) error {
		cfg["targetId"] = u.target
		return u.f.disp.runAction(context.Background(), row, u.f.stepOf(t, u.f.action(t, "r-"+uuid.NewString()[:6], "pfsense_restart", "post_deploy", cfg)), req)
	}
	if err := run(map[string]any{"mode": "none"}); err != nil || len(f.php) != 0 {
		t.Fatalf("none: %v php=%d", err, len(f.php))
	}
	if err := run(map[string]any{"mode": "all"}); err != nil || len(f.php) != 2 {
		t.Fatalf("all: %v php=%d", err, len(f.php))
	}
	if err := run(map[string]any{"mode": "selected", "services": []string{"ipsec"}}); err != nil || len(f.php) != 5 {
		t.Fatalf("selected: %v php=%d", err, len(f.php))
	}
	runs := u.f.runs(t, u.g)
	if len(runs) != 3 || !strings.Contains(runs[1].stdout, "restarted: WebGUI") || runs[2].stdout != "restarted: IPsec" {
		t.Fatalf("runs = %+v", runs)
	}
	bad := u.f.action(t, "bad", "pfsense_restart", "post_deploy", map[string]any{"targetId": uuid.New(), "mode": "all"})
	if err := u.f.disp.runAction(context.Background(), row, u.f.stepOf(t, bad), req); err == nil {
		t.Fatal("expected error")
	}
}

func TestPfSenseRestartStepSuppressesBuiltIn(t *testing.T) {
	u := newStepSetup(t)
	f := &fakePF{list: `[{"refid":"abc","descr":"web"}]`, phpOut: pfPHPOut}
	srv := httptest.NewServer(f)
	defer srv.Close()
	u.pfSenseTarget(t, srv)
	// The fake "pfsense" Target type stands in for the real one.
	u.sec.Code = "pfsense"
	u.f.reg.Register(u.sec)
	a := u.f.action(t, "restart", "pfsense_restart", "post_deploy", map[string]any{"targetId": u.target, "mode": "all"})
	u.f.setSteps(t, u.g, step(a))
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err != nil {
		t.Fatal(err)
	}
	if len(u.sec.Calls) != 1 || string(u.sec.Calls[0].GrantOptions) != `{"pfsenseRestart":{"mode":"none"}}` {
		t.Fatalf("calls = %+v", u.sec.Calls)
	}
	if len(f.php) != 2 { // usage lookup, then the restart
		t.Fatalf("php = %d", len(f.php))
	}
	// Without the step nothing is suppressed.
	u.f.setSteps(t, u.g)
	u.f.pending(t, u.g, u.ver)
	if err := u.f.disp.Deploy(context.Background(), u.g, u.ver); err != nil {
		t.Fatal(err)
	}
	if len(u.sec.Calls) != 2 || strings.Contains(string(u.sec.Calls[1].GrantOptions), "pfsenseRestart") {
		t.Fatalf("calls = %+v", u.sec.Calls)
	}
}
