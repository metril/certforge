//go:build integration

package deploy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx/sshxtest"
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

func (f *dispatcherFixture) setPostAction(t *testing.T, grantID uuid.UUID, pa PostAction) {
	t.Helper()
	b, _ := json.Marshal(pa)
	if _, err := f.pool.Exec(context.Background(), `UPDATE client_cert_grants SET post_action = $2 WHERE id = $1`, grantID, b); err != nil {
		t.Fatal(err)
	}
}

type recordedRun struct {
	phase, stdout, stderr string
	argv                  []string
	exit                  int
	client                *uuid.UUID
	target                *uuid.UUID
}

func (f *dispatcherFixture) runs(t *testing.T, grantID uuid.UUID) []recordedRun {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT phase, argv, exit_code, stdout, stderr, client_id, deploy_target_id FROM hook_runs WHERE grant_id = $1 ORDER BY ran_at, id`, grantID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []recordedRun
	for rows.Next() {
		var r recordedRun
		if err := rows.Scan(&r.phase, &r.argv, &r.exit, &r.stdout, &r.stderr, &r.client, &r.target); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func postActionSetup(t *testing.T, s *sshxtest.Server, pa func(ssh uuid.UUID) PostAction) (*dispatcherFixture, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	f := newDispatcherFixture(t)
	target, _ := f.target(t, "plain", targets.Server, targets.Never, map[string]any{"url": "https://x.example.test"})
	ssh := f.sshTarget(t, s, s.Port(t))
	cert := f.cert(t, "web")
	ver := f.version(t, cert, "1", false)
	g := f.grant(t, cert, target)
	f.setPostAction(t, g, pa(ssh))
	f.pending(t, g, ver)
	return f, g, ver, target
}

func TestPostActionSuccessRecorded(t *testing.T) {
	s := sshxtest.Start(t, nil)
	f, g, ver, target := postActionSetup(t, s, func(ssh uuid.UUID) PostAction {
		return PostAction{SSHTargetID: ssh, Command: "systemctl reload nginx", TimeoutSeconds: 10}
	})
	if err := f.disp.Deploy(context.Background(), g, ver); err != nil {
		t.Fatal(err)
	}
	if st := f.status(t, g); st != "deployed" {
		t.Fatalf("status = %s", st)
	}
	if len(s.Cmds) != 1 || s.Cmds[0] != "systemctl reload nginx" {
		t.Fatalf("cmds = %q", s.Cmds)
	}
	runs := f.runs(t, g)
	if len(runs) != 1 || runs[0].phase != "post_deploy" || runs[0].exit != 0 || runs[0].client != nil ||
		runs[0].target == nil || *runs[0].target != target || strings.Join(runs[0].argv, "|") != "ssh|127.0.0.1|systemctl reload nginx" {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestPostActionNonZeroFailsDeployment(t *testing.T) {
	s := sshxtest.Start(t, nil)
	s.Exit = 3
	f, g, ver, _ := postActionSetup(t, s, func(ssh uuid.UUID) PostAction {
		return PostAction{SSHTargetID: ssh, Command: "false", TimeoutSeconds: 10}
	})
	if err := f.disp.Deploy(context.Background(), g, ver); err == nil {
		t.Fatal("expected error")
	}
	if st := f.status(t, g); st != "failed" {
		t.Fatalf("status = %s", st)
	}
	if le := f.lastError(t, g); !strings.Contains(le, "deployed, but post action: exit 3") || strings.Contains(le, "s3cret") {
		t.Fatalf("last_error = %q", le)
	}
	if runs := f.runs(t, g); len(runs) != 1 || runs[0].exit != 3 {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestPostActionDialFailureRecorded(t *testing.T) {
	s := sshxtest.Start(t, nil)
	f, g, ver, _ := postActionSetup(t, s, func(ssh uuid.UUID) PostAction {
		return PostAction{SSHTargetID: ssh, Command: "true", TimeoutSeconds: 5}
	})
	// Point the ssh target at a closed port.
	if _, err := f.pool.Exec(context.Background(), `UPDATE deploy_targets SET config = jsonb_set(config, '{port}', '1') WHERE type = 'ssh'`); err != nil {
		t.Fatal(err)
	}
	if err := f.disp.Deploy(context.Background(), g, ver); err == nil {
		t.Fatal("expected error")
	}
	if st := f.status(t, g); st != "failed" {
		t.Fatalf("status = %s", st)
	}
	runs := f.runs(t, g)
	if len(runs) != 1 || runs[0].exit != -1 || runs[0].stderr == "" {
		t.Fatalf("runs = %+v", runs)
	}
}
