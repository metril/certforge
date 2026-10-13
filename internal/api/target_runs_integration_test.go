//go:build integration

package api

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
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
	l := gen.ActionRunList(res.(gen.ListTargetHookRuns200JSONResponse))
	if len(l.Items) != 2 || l.NextCursor == nil || l.Items[0].ExitCode != 2 {
		t.Fatalf("page 1 = %+v", l)
	}
	res, err = f.srv.ListTargetHookRuns(f.as("viewer"), gen.ListTargetHookRunsRequestObject{OrgId: f.org, Id: tid, Params: gen.ListTargetHookRunsParams{Limit: &lim, Cursor: l.NextCursor}})
	if err != nil {
		t.Fatal(err)
	}
	if l2 := gen.ActionRunList(res.(gen.ListTargetHookRuns200JSONResponse)); len(l2.Items) != 1 || l2.NextCursor != nil {
		t.Fatalf("page 2 = %+v", l2)
	}
	_, err = f.srv.ListTargetHookRuns(f.as("viewer"), gen.ListTargetHookRunsRequestObject{OrgId: f.org, Id: uuid.New()})
	if problemStatus(err) != 404 {
		t.Fatalf("unknown target: %v", err)
	}
}
