//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/meta"
)

func stepsOf(ids ...uuid.UUID) []gen.GrantStep {
	out := []gen.GrantStep{}
	for _, id := range ids {
		var s gen.GrantStep
		_ = s.FromGrantStepAction(gen.GrantStepAction{Action: id})
		out = append(out, s)
	}
	return out
}

func stepsPtr(ids ...uuid.UUID) *[]gen.GrantStep { s := stepsOf(ids...); return &s }

func groupStep(id uuid.UUID) gen.GrantStep {
	var s gen.GrantStep
	_ = s.FromGrantStepGroup(gen.GrantStepGroup{Group: id})
	return s
}

// problemTitle is the HTTPError title ("Invalid steps[0]") of err.
func problemTitle(err error) string {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Title
	}
	return ""
}

func actionIn(name, kind string, cfg map[string]interface{}) *gen.ActionInput {
	return &gen.ActionInput{Name: name, Kind: gen.ActionKind(kind), Phase: gen.ActionPhase("post_deploy"), Config: cfg}
}

func (f *agentFixture) mkAction(t *testing.T, in *gen.ActionInput) gen.Action {
	t.Helper()
	res, err := f.srv.CreateAction(f.as("operator"), gen.CreateActionRequestObject{OrgId: f.org, Body: in})
	if err != nil {
		t.Fatalf("create action %s: %v", in.Name, err)
	}
	return gen.Action(res.(gen.CreateAction201JSONResponse))
}

func (f *agentFixture) execAction(t *testing.T, name string) gen.Action {
	return f.mkAction(t, actionIn(name, "exec", map[string]interface{}{"argv": []interface{}{"/bin/true"}}))
}

func (f *agentFixture) waitAction(t *testing.T, name string) gen.Action {
	return f.mkAction(t, actionIn(name, "wait", map[string]interface{}{"seconds": 1}))
}

func httpActionCfg(auth string) map[string]interface{} {
	return map[string]interface{}{"method": "POST", "url": "https://hooks.example.com/x", "secretHeaders": map[string]interface{}{"Authorization": auth}}
}

func TestActionsCRUDSecrets(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	ctx := context.Background()
	a := f.mkAction(t, actionIn("notify-hook", "http", httpActionCfg("Bearer s3cret")))
	if a.RunsOn != "server" || len(a.SecretKeys) != 1 || a.SecretKeys[0] != "secretHeaders" || a.TimeoutSeconds != 60 {
		t.Fatalf("action %+v", a)
	}
	if _, ok := a.Config["secretHeaders"]; ok {
		t.Fatal("secret echoed in create")
	}
	storedSecret := func() string {
		cur, err := f.q.GetAction(ctx, sqlcgen.GetActionParams{ID: a.Id, OrgID: f.org})
		if err != nil || len(cur.SecretCfg) == 0 {
			return ""
		}
		pt, err := f.box.Open(ctx, cur.SecretCfg)
		if err != nil {
			t.Fatal(err)
		}
		return string(pt)
	}
	if !strings.Contains(storedSecret(), "Bearer s3cret") {
		t.Fatal("secret not stored")
	}
	for name, get := range map[string]func() any{
		"get": func() any {
			r, err := f.srv.GetAction(f.as("viewer"), gen.GetActionRequestObject{OrgId: f.org, Id: a.Id})
			if err != nil {
				t.Fatal(err)
			}
			return r
		},
		"list": func() any {
			r, err := f.srv.ListActions(f.as("viewer"), gen.ListActionsRequestObject{OrgId: f.org})
			if err != nil {
				t.Fatal(err)
			}
			return r
		},
	} {
		if b, _ := json.Marshal(get()); strings.Contains(string(b), "s3cret") {
			t.Fatalf("%s echoes the secret: %s", name, b)
		}
	}
	update := func(cfg map[string]interface{}) (gen.Action, error) {
		res, err := f.srv.UpdateAction(op, gen.UpdateActionRequestObject{OrgId: f.org, Id: a.Id, Body: actionIn("notify-hook", "http", cfg)})
		if err != nil {
			return gen.Action{}, err
		}
		return gen.Action(res.(gen.UpdateAction200JSONResponse)), nil
	}
	// "__unchanged__" and omission both keep the stored secret.
	for _, cfg := range []map[string]interface{}{
		{"method": "PUT", "url": "https://hooks.example.com/y", "secretHeaders": "__unchanged__"},
		{"method": "PUT", "url": "https://hooks.example.com/z"},
	} {
		u, err := update(cfg)
		if err != nil || len(u.SecretKeys) != 1 || !strings.Contains(storedSecret(), "Bearer s3cret") {
			t.Fatalf("keep: %+v %v", u, err)
		}
	}
	// A replacement is sealed; {} clears.
	if _, err := update(httpActionCfg("Bearer new")); err != nil || !strings.Contains(storedSecret(), "Bearer new") {
		t.Fatalf("replace: %v", err)
	}
	u, err := update(map[string]interface{}{"method": "GET", "url": "https://hooks.example.com/z", "secretHeaders": map[string]interface{}{}})
	if err != nil || len(u.SecretKeys) != 0 || storedSecret() != "" {
		t.Fatalf("clear: %+v %v", u, err)
	}
	_, err = update(map[string]interface{}{"method": "GET", "url": "https://hooks.example.com/z", "secretHeaders": "__unchanged__"})
	wantStatus(t, err, 422)
	if _, err := f.srv.DeleteAction(op, gen.DeleteActionRequestObject{OrgId: f.org, Id: a.Id}); err != nil {
		t.Fatal(err)
	}
	if f.auditCount(t, "action.create") != 1 || f.auditCount(t, "action.update") != 4 || f.auditCount(t, "action.delete") != 1 {
		t.Fatal("action audit")
	}
	var leaked int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE details::text LIKE '%s3cret%' OR details::text LIKE '%Bearer%'`).Scan(&leaked)
	if leaked != 0 {
		t.Fatal("secret in audit")
	}
}

func TestActionKindsValidation(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	create := func(in *gen.ActionInput) error {
		_, err := f.srv.CreateAction(op, gen.CreateActionRequestObject{OrgId: f.org, Body: in})
		return err
	}
	wantStatus(t, create(actionIn("a", "exec", map[string]interface{}{"argv": []interface{}{"sh", "-c", "x"}})), 422)
	wantStatus(t, create(actionIn("a", "nope", map[string]interface{}{})), 422)
	wantStatus(t, create(actionIn("a", "restart", map[string]interface{}{"target": "nginx"})), 422)
	wantStatus(t, create(actionIn("a", "wait", map[string]interface{}{"seconds": 999})), 422)
	bad := actionIn("a", "wait", map[string]interface{}{"seconds": 5})
	bad.Phase = "later"
	wantStatus(t, create(bad), 422)
	if err := create(actionIn("r", "restart", map[string]interface{}{"target": "docker:nginx"})); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, create(actionIn("r", "wait", map[string]interface{}{"seconds": 5})), 409)
	// Moving an in-use action to the other side is a conflict.
	a := f.execAction(t, "e")
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout, Steps: stepsPtr(a.Id)}}); err != nil {
		t.Fatal(err)
	}
	_, err := f.srv.UpdateAction(op, gen.UpdateActionRequestObject{OrgId: f.org, Id: a.Id, Body: actionIn("e", "wait", map[string]interface{}{"seconds": 2})})
	wantStatus(t, err, 409)
}

func TestActionTargetAndChannelRefs(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	sshT := f.sshTargetIn(t, f.org, "ssh")
	vaultT := f.sshTargetIn(t, f.org, "vault-kv")
	otherOrg := f.sshTargetIn(t, dbtest.Org(t, f.pool), "ssh")
	create := func(kind string, cfg map[string]interface{}) error {
		_, err := f.srv.CreateAction(op, gen.CreateActionRequestObject{OrgId: f.org, Body: actionIn("a-"+uuid.NewString()[:6], kind, cfg)})
		return err
	}
	for name, id := range map[string]uuid.UUID{"wrong type": vaultT, "other org": otherOrg, "missing": uuid.New()} {
		err := create("ssh", map[string]interface{}{"targetId": id.String(), "command": "true"})
		if problemStatus(err) != 422 || problemTitle(err) != "Invalid config.targetId" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := create("ssh", map[string]interface{}{"targetId": sshT.String(), "command": "true"}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, create("truenas_restart", map[string]interface{}{"targetId": sshT.String()}), 422)
	wantStatus(t, create("notify", map[string]interface{}{"channelId": uuid.NewString()}), 422)
	ch, err := f.q.CreateNotificationChannel(context.Background(), sqlcgen.CreateNotificationChannelParams{OrgID: f.org, Name: "ops", Type: "webhook",
		Config: []byte(`{}`), Events: []string{}, MinSeverity: "info", Enabled: true, StoredSecretKeys: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := create("notify", map[string]interface{}{"channelId": ch.ID.String()}); err != nil {
		t.Fatal(err)
	}
}

func TestActionsNeedDeliveryWrite(t *testing.T) {
	f := newAgentFixture(t)
	reader := apiKeyPrincipal(f.org, []string{"delivery:read"})
	_, err := f.srv.CreateAction(reader, gen.CreateActionRequestObject{OrgId: f.org, Body: actionIn("w", "wait", map[string]interface{}{"seconds": 1})})
	wantStatus(t, err, 403)
	_, err = f.srv.CreateActionGroup(reader, gen.CreateActionGroupRequestObject{OrgId: f.org, Body: &gen.ActionGroupInput{Name: "g", ActionIds: []uuid.UUID{uuid.New()}}})
	wantStatus(t, err, 403)
	if _, err := f.srv.ListActions(reader, gen.ListActionsRequestObject{OrgId: f.org}); err != nil {
		t.Fatal(err)
	}
	// Server steps on a grant need delivery:write on top of clients:write.
	a := f.waitAction(t, "w")
	targetID, _ := f.serverTarget(t, "vault", nil)
	cert1, _ := f.currentCert(t, "web")
	cert2, _ := f.currentCert(t, "api")
	narrow := apiKeyPrincipal(f.org, []string{"clients:write"})
	wide := apiKeyPrincipal(f.org, []string{"clients:write", "delivery:write"})
	in := func(c uuid.UUID, s *[]gen.GrantStep) gen.CreateServerGrantRequestObject {
		return gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID, Body: &gen.ServerGrantInput{CertificateId: c, Steps: s}}
	}
	if _, err := f.srv.CreateServerGrant(narrow, in(cert1, stepsPtr(a.Id))); problemStatus(err) != 403 {
		t.Fatalf("narrow create with steps: %v", err)
	}
	if _, err := f.srv.CreateServerGrant(narrow, in(cert1, nil)); err != nil {
		t.Fatal(err)
	}
	res, err := f.srv.CreateServerGrant(wide, in(cert2, stepsPtr(a.Id)))
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)
	if len(g.Steps) != 1 {
		t.Fatalf("steps %+v", g.Steps)
	}
	up := func(ctx context.Context, s []gen.GrantStep) error {
		_, err := f.srv.UpdateGrant(ctx, gen.UpdateGrantRequestObject{OrgId: f.org, Id: g.Id, Body: &gen.GrantUpdate{Delivery: push(), Steps: s}})
		return err
	}
	if problemStatus(up(narrow, []gen.GrantStep{})) != 403 || problemStatus(up(narrow, stepsOf(a.Id))) != 403 {
		t.Fatal("narrow key changed steps")
	}
	if err := up(wide, []gen.GrantStep{}); err != nil {
		t.Fatal(err)
	}
}

func TestGrantStepsRunsOnAndLimits(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	ex := f.execAction(t, "e")
	wt := f.waitAction(t, "w")
	grp, err := f.srv.CreateActionGroup(op, gen.CreateActionGroupRequestObject{OrgId: f.org, Body: &gen.ActionGroupInput{Name: "mixed", ActionIds: []uuid.UUID{ex.Id, wt.Id}}})
	if err != nil {
		t.Fatal(err)
	}
	group := grp.(gen.CreateActionGroup201JSONResponse)
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	targetID, _ := f.serverTarget(t, "vault", nil)
	cert2, _ := f.currentCert(t, "api")
	many := make([]uuid.UUID, 33)
	for i := range many {
		many[i] = ex.Id
	}
	client := func(s []gen.GrantStep) error {
		_, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
			Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout, Steps: &s}})
		return err
	}
	server := func(s []gen.GrantStep) error {
		_, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
			Body: &gen.ServerGrantInput{CertificateId: cert2, Steps: &s}})
		return err
	}
	// Client grant: a server action, and a group holding one, are 422 on steps[i].
	for name, s := range map[string][]gen.GrantStep{"action": stepsOf(ex.Id, wt.Id), "group": {groupStep(group.Id)}} {
		err := client(s)
		if problemStatus(err) != 422 || !strings.HasPrefix(problemTitle(err), "Invalid steps[") {
			t.Errorf("client %s: %v", name, err)
		}
	}
	// Server grant: an agent action is 422 on steps[0].
	if err := server(stepsOf(ex.Id)); problemStatus(err) != 422 || problemTitle(err) != "Invalid steps[0]" {
		t.Errorf("server exec: %v", err)
	}
	if err := server([]gen.GrantStep{groupStep(group.Id)}); problemStatus(err) != 422 {
		t.Errorf("server group: %v", err)
	}
	wantStatus(t, client(stepsOf(many...)), 422)
	wantStatus(t, server(stepsOf(many...)), 422)
	wantStatus(t, client(stepsOf(uuid.New())), 422)
	wantStatus(t, server(stepsOf(uuid.New())), 422)
	if err := client(stepsOf(ex.Id)); err != nil {
		t.Fatal(err)
	}
	if err := server(stepsOf(wt.Id)); err != nil {
		t.Fatal(err)
	}
}

func TestActionDeleteInUse(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	ex := f.execAction(t, "e")
	other := f.execAction(t, "o")
	gres, err := f.srv.CreateActionGroup(op, gen.CreateActionGroupRequestObject{OrgId: f.org, Body: &gen.ActionGroupInput{Name: "g", ActionIds: []uuid.UUID{other.Id}}})
	if err != nil {
		t.Fatal(err)
	}
	group := gen.ActionGroup(gres.(gen.CreateActionGroup201JSONResponse))
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout, Steps: &[]gen.GrantStep{stepsOf(ex.Id)[0], groupStep(group.Id)}}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateGrant201JSONResponse)
	delA := func(id uuid.UUID) error {
		_, err := f.srv.DeleteAction(op, gen.DeleteActionRequestObject{OrgId: f.org, Id: id})
		return err
	}
	delG := func(id uuid.UUID) error {
		_, err := f.srv.DeleteActionGroup(op, gen.DeleteActionGroupRequestObject{OrgId: f.org, Id: id})
		return err
	}
	err = delA(ex.Id)
	wantStatus(t, err, 409)
	if !strings.Contains(err.Error(), "web-1") {
		t.Fatalf("409 does not name the client: %v", err)
	}
	err = delA(other.Id) // member of a group
	wantStatus(t, err, 409)
	if !strings.Contains(err.Error(), "group g") {
		t.Fatalf("409 does not name the group: %v", err)
	}
	wantStatus(t, delG(group.Id), 409) // used by a grant step
	if _, err := f.srv.UpdateGrant(op, gen.UpdateGrantRequestObject{OrgId: f.org, Id: g.Id, Body: &gen.GrantUpdate{
		Delivery: push(), LayoutId: &layout, Steps: []gen.GrantStep{}}}); err != nil {
		t.Fatal(err)
	}
	if err := delA(ex.Id); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, delA(other.Id), 409) // still in the group
	if err := delG(group.Id); err != nil {
		t.Fatal(err)
	}
	if err := delA(other.Id); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, delA(other.Id), 404)
}

func TestActionGroupsCRUD(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	a, b := f.execAction(t, "a"), f.execAction(t, "b")
	foreign, err := f.q.CreateAction(context.Background(), sqlcgen.CreateActionParams{OrgID: dbtest.Org(t, f.pool), Name: "x", Kind: "exec", Phase: "post_deploy",
		Config: []byte(`{"argv":["/bin/true"]}`), TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	create := func(name string, ids ...uuid.UUID) (gen.ActionGroup, error) {
		res, err := f.srv.CreateActionGroup(op, gen.CreateActionGroupRequestObject{OrgId: f.org, Body: &gen.ActionGroupInput{Name: name, ActionIds: ids}})
		if err != nil {
			return gen.ActionGroup{}, err
		}
		return gen.ActionGroup(res.(gen.CreateActionGroup201JSONResponse)), nil
	}
	_, err = create("empty")
	wantStatus(t, err, 422)
	_, err = create("foreign", foreign.ID)
	wantStatus(t, err, 422)
	_, err = create("unknown", uuid.New())
	wantStatus(t, err, 422)
	many := make([]uuid.UUID, 33)
	for i := range many {
		many[i] = a.Id
	}
	_, err = create("many", many...)
	wantStatus(t, err, 422)
	g, err := create("pair", b.Id, a.Id)
	if err != nil || len(g.ActionIds) != 2 || g.ActionIds[0] != b.Id {
		t.Fatalf("group %+v %v", g, err)
	}
	_, err = create("pair", a.Id)
	wantStatus(t, err, 409)
	up, err := f.srv.UpdateActionGroup(op, gen.UpdateActionGroupRequestObject{OrgId: f.org, Id: g.Id, Body: &gen.ActionGroupInput{Name: "pair", ActionIds: []uuid.UUID{a.Id, b.Id}}})
	if err != nil || up.(gen.UpdateActionGroup200JSONResponse).ActionIds[0] != a.Id {
		t.Fatalf("update %v", err)
	}
	l, err := f.srv.ListActionGroups(f.as("viewer"), gen.ListActionGroupsRequestObject{OrgId: f.org})
	if err != nil || len(l.(gen.ListActionGroups200JSONResponse).Items) != 1 {
		t.Fatalf("list %v", err)
	}
	if _, err := f.srv.GetActionGroup(f.as("viewer"), gen.GetActionGroupRequestObject{OrgId: f.org, Id: uuid.New()}); problemStatus(err) != 404 {
		t.Fatalf("unknown get: %v", err)
	}
	if _, err := f.srv.DeleteActionGroup(op, gen.DeleteActionGroupRequestObject{OrgId: f.org, Id: g.Id}); err != nil {
		t.Fatal(err)
	}
	if f.auditCount(t, "action_group.create") != 1 || f.auditCount(t, "action_group.update") != 1 || f.auditCount(t, "action_group.delete") != 1 {
		t.Fatal("group audit")
	}
}

func TestMetaSchemasListsActionKinds(t *testing.T) {
	f := newAgentFixture(t)
	f.srv.d.Meta = meta.NewRegistry()
	res, err := f.srv.GetMetaSchemas(f.as("viewer"), gen.GetMetaSchemasRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	m := gen.MetaSchemas(res.(gen.GetMetaSchemas200JSONResponse))
	if len(m.Actions) != 11 {
		t.Fatalf("%d action kinds", len(m.Actions))
	}
	seen := map[string]gen.ActionSchemaEntry{}
	for _, e := range m.Actions {
		seen[e.Code] = e
	}
	if e := seen["exec"]; e.RunsOn != "agent" || e.Schema == nil {
		t.Fatalf("exec %+v", e)
	}
	if e := seen["pfsense_restart"]; e.RunsOn != "server" || len(e.TargetTypes) != 1 || e.TargetTypes[0] != "pfsense" || e.PhaseHint != "post_deploy" {
		t.Fatalf("pfsense_restart %+v", e)
	}
}

func TestActionRunsShowNameAndKind(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	a := f.execAction(t, "mine")
	c := f.activeClient(t, "web-1")
	if _, err := f.pool.Exec(ctx, `INSERT INTO hook_runs (client_id, hook_id, phase, argv, exit_code) VALUES ($1, $2, 'post_deploy', '{/bin/true}', 0)`, c.ID, a.Id); err != nil {
		t.Fatal(err)
	}
	res, err := f.srv.ListClientHookRuns(f.as("viewer"), gen.ListClientHookRunsRequestObject{OrgId: f.org, Id: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	runs := res.(gen.ListClientHookRuns200JSONResponse).Items
	if len(runs) != 1 || runs[0].ActionName != "mine" || runs[0].ActionKind != "exec" || runs[0].ActionId == nil || *runs[0].ActionId != a.Id {
		t.Fatalf("runs %+v", runs)
	}
	tid := f.sshTargetIn(t, f.org, "ssh")
	if _, err := f.pool.Exec(ctx, `INSERT INTO hook_runs (client_id, deploy_target_id, hook_id, phase, argv, exit_code) VALUES (NULL, $1, $2, 'post_deploy', '{ssh}', 0)`, tid, a.Id); err != nil {
		t.Fatal(err)
	}
	tr, err := f.srv.ListTargetHookRuns(f.as("viewer"), gen.ListTargetHookRunsRequestObject{OrgId: f.org, Id: tid})
	if err != nil {
		t.Fatal(err)
	}
	if items := tr.(gen.ListTargetHookRuns200JSONResponse).Items; len(items) != 1 || items[0].ActionName != "mine" || items[0].ActionKind != "exec" {
		t.Fatalf("target runs %+v", items)
	}
}
