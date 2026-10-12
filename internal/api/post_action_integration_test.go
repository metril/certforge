//go:build integration

package api

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/db/dbtest"
)

func (f *agentFixture) sshTargetIn(t *testing.T, org uuid.UUID, typ string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO deploy_targets (org_id, name, type, runs_on, config) VALUES ($1, $2, $3, 'server', '{}') RETURNING id`,
		org, "t-"+uuid.NewString()[:8], typ).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestServerGrantPostActionValidation(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	targetID, _ := f.serverTarget(t, "vault", nil)
	certID, _ := f.currentCert(t, "web")
	sshT := f.sshTargetIn(t, f.org, "ssh")
	otherOrgSSH := f.sshTargetIn(t, dbtest.Org(t, f.pool), "ssh")
	vaultT := f.sshTargetIn(t, f.org, "vault-kv")
	create := func(pa *gen.PostAction) error {
		_, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
			Body: &gen.ServerGrantInput{CertificateId: certID, PostAction: pa}})
		return err
	}
	for name, pa := range map[string]*gen.PostAction{
		"wrong type":    {TargetId: vaultT, Command: "true"},
		"other org":     {TargetId: otherOrgSSH, Command: "true"},
		"missing":       {TargetId: uuid.New(), Command: "true"},
		"empty command": {TargetId: sshT, Command: "  "},
		"long command":  {TargetId: sshT, Command: string(make([]byte, 600))},
	} {
		if err := create(pa); problemStatus(err) != 422 {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	timeout := 2
	if err := create(&gen.PostAction{TargetId: sshT, Command: "true", TimeoutSeconds: &timeout}); problemStatus(err) != 422 {
		t.Errorf("timeout 2: %v", err)
	}
	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID, PostAction: &gen.PostAction{TargetId: sshT, Command: " reload "}}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)
	if g.PostAction == nil || g.PostAction.Command != "reload" || g.PostAction.TimeoutSeconds == nil || *g.PostAction.TimeoutSeconds != 60 {
		t.Fatalf("postAction = %+v", g.PostAction)
	}
	// Removing the ssh target while a post action uses it is a conflict.
	if _, err := f.srv.DeleteDeployTarget(f.as("admin"), gen.DeleteDeployTargetRequestObject{OrgId: f.org, Id: sshT}); problemStatus(err) != 409 {
		t.Fatalf("delete in-use ssh target: %v", err)
	}
	// Update clears it.
	up, err := f.srv.UpdateGrant(op, gen.UpdateGrantRequestObject{OrgId: f.org, Id: g.Id, Body: &gen.GrantUpdate{Delivery: gen.GrantDelivery("push")}})
	if err != nil {
		t.Fatal(err)
	}
	if up.(gen.UpdateGrant200JSONResponse).PostAction != nil {
		t.Fatal("post action not cleared")
	}
}

func TestListTargetHookRuns(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	tid := f.sshTargetIn(t, f.org, "ssh")
	for i := 0; i < 3; i++ {
		if _, err := f.pool.Exec(ctx, `INSERT INTO hook_runs (client_id, deploy_target_id, phase, argv, exit_code) VALUES (NULL, $1, 'post_deploy', '{ssh,h,cmd}', $2)`, tid, i); err != nil {
			t.Fatal(err)
		}
	}
	lim := 2
	res, err := f.srv.ListTargetHookRuns(f.as("viewer"), gen.ListTargetHookRunsRequestObject{OrgId: f.org, Id: tid, Params: gen.ListTargetHookRunsParams{Limit: &lim}})
	if err != nil {
		t.Fatal(err)
	}
	l := gen.HookRunList(res.(gen.ListTargetHookRuns200JSONResponse))
	if len(l.Items) != 2 || l.NextCursor == nil || l.Items[0].ExitCode != 2 {
		t.Fatalf("page 1 = %+v", l)
	}
	res, err = f.srv.ListTargetHookRuns(f.as("viewer"), gen.ListTargetHookRunsRequestObject{OrgId: f.org, Id: tid, Params: gen.ListTargetHookRunsParams{Limit: &lim, Cursor: l.NextCursor}})
	if err != nil {
		t.Fatal(err)
	}
	if l2 := gen.HookRunList(res.(gen.ListTargetHookRuns200JSONResponse)); len(l2.Items) != 1 || l2.NextCursor != nil {
		t.Fatalf("page 2 = %+v", l2)
	}
	_, err = f.srv.ListTargetHookRuns(f.as("viewer"), gen.ListTargetHookRunsRequestObject{OrgId: f.org, Id: uuid.New()})
	if problemStatus(err) != 404 {
		t.Fatalf("unknown target: %v", err)
	}
}

func TestPostActionNeedsDeliveryWrite(t *testing.T) {
	f := newAgentFixture(t)
	targetID, _ := f.serverTarget(t, "vault", nil)
	certID, _ := f.currentCert(t, "web")
	cert2, _ := f.currentCert(t, "api")
	sshT := f.sshTargetIn(t, f.org, "ssh")
	pa := &gen.PostAction{TargetId: sshT, Command: "true"}
	narrow := apiKeyPrincipal(f.org, []string{"clients:write"})
	wide := apiKeyPrincipal(f.org, []string{"clients:write", "delivery:write"})
	in := func(c uuid.UUID, p *gen.PostAction) gen.CreateServerGrantRequestObject {
		return gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID, Body: &gen.ServerGrantInput{CertificateId: c, PostAction: p}}
	}
	if _, err := f.srv.CreateServerGrant(narrow, in(certID, pa)); problemStatus(err) != 403 {
		t.Fatalf("create with postAction: %v", err)
	}
	if _, err := f.srv.CreateServerGrant(narrow, in(certID, nil)); err != nil {
		t.Fatalf("create without: %v", err)
	}
	res, err := f.srv.CreateServerGrant(wide, in(cert2, pa))
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateServerGrant201JSONResponse).Id
	up := func(ctx context.Context, p *gen.PostAction) error {
		_, err := f.srv.UpdateGrant(ctx, gen.UpdateGrantRequestObject{OrgId: f.org, Id: id, Body: &gen.GrantUpdate{Delivery: gen.GrantDelivery("push"), PostAction: p}})
		return err
	}
	if problemStatus(up(narrow, nil)) != 403 || problemStatus(up(narrow, pa)) != 403 {
		t.Fatal("narrow key changed a post action")
	}
	if err := up(wide, pa); err != nil {
		t.Fatal(err)
	}
}
