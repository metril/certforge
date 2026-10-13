//go:build integration

package agents

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/actions"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func (f *syncFixture) action(t *testing.T, name, kind, cfg string) uuid.UUID {
	t.Helper()
	a, err := f.q.CreateAction(context.Background(), sqlcgen.CreateActionParams{OrgID: f.org, Name: name, Kind: kind,
		Phase: "post_deploy", Config: []byte(cfg), TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func (f *syncFixture) group(t *testing.T, name string, ids ...uuid.UUID) uuid.UUID {
	t.Helper()
	g, err := f.q.CreateActionGroup(context.Background(), sqlcgen.CreateActionGroupParams{OrgID: f.org, Name: name, ActionIds: ids})
	if err != nil {
		t.Fatal(err)
	}
	return g.ID
}

func TestGrantStepsValidation(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()
	cert := f.cert(t, "a")
	tid := f.fileTarget(t, "file", t.TempDir(), nil)
	c := f.client(t, "c1")
	e1 := f.action(t, "e1", "exec", `{"argv":["/bin/true"]}`)
	e2 := f.action(t, "e2", "restart", `{"target":"docker:web"}`)
	w := f.action(t, "w", "wait", `{"seconds":1}`)
	srvGroup := f.group(t, "srv", e1, w)
	agentGroup := f.group(t, "ag", e1, e2)
	act := func(id uuid.UUID) actions.Step { return actions.Step{Action: &id} }
	grp := func(id uuid.UUID) actions.Step { return actions.Step{Group: &id} }
	create := func(steps ...actions.Step) error {
		_, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: cert, Delivery: "pull", TargetID: &tid, Steps: steps})
		return err
	}

	wantKind(t, create(act(e1), act(w)), KindInvalid, "steps[1]")
	wantKind(t, create(act(e1), grp(srvGroup)), KindInvalid, "steps[1]")
	wantKind(t, create(act(uuid.New())), KindInvalid, "steps[0]")
	wantKind(t, create(grp(uuid.New())), KindInvalid, "steps[0]")
	wantKind(t, create(actions.Step{}), KindInvalid, "steps[0]")
	over := make([]actions.Step, 33)
	for i := range over {
		over[i] = act(e1)
	}
	wantKind(t, create(over...), KindInvalid, "steps")
	// Fits as 17 steps but expands past 32 actions.
	big := make([]actions.Step, 17)
	for i := range big {
		big[i] = grp(agentGroup)
	}
	wantKind(t, create(big...), KindInvalid, "steps[16]")

	gid, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: cert, Delivery: "pull", TargetID: &tid,
		Steps: []actions.Step{act(e2), grp(agentGroup)}})
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := f.pool.QueryRow(ctx, `SELECT steps::text FROM client_cert_grants WHERE id = $1`, gid).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	want := `[{"action": "` + e2.String() + `"}, {"group": "` + agentGroup.String() + `"}]`
	if raw != want {
		t.Fatalf("steps %s, want %s", raw, want)
	}
}

func TestAssignmentsHooksFollowStepOrderWithGroups(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()
	cert := f.cert(t, "a")
	f.setCurrent(t, cert, f.version(t, cert, 1, true))
	tid := f.fileTarget(t, "file", t.TempDir(), nil)
	c := f.client(t, "c1")
	a := f.action(t, "a", "exec", `{"argv":["/bin/a"]}`)
	b := f.action(t, "b", "restart", `{"target":"docker:b"}`)
	d := f.action(t, "d", "exec", `{"argv":["/bin/d"]}`)
	g := f.group(t, "g", b, d)
	steps := []actions.Step{{Group: &g}, {Action: &a}}
	if _, err := f.svc.CreateGrant(ctx, f.org, c.ID, GrantInput{CertID: cert, Delivery: "pull", TargetID: &tid, Steps: steps}); err != nil {
		t.Fatal(err)
	}
	as, err := f.svc.Assignments(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(as.Grants) != 1 {
		t.Fatalf("grants %d", len(as.Grants))
	}
	var got []uuid.UUID
	for _, h := range as.Grants[0].Hooks {
		got = append(got, h.ID)
	}
	if len(got) != 3 || got[0] != b || got[1] != d || got[2] != a {
		t.Fatalf("hook order %v, want [%s %s %s]", got, b, d, a)
	}
}
