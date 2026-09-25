//go:build integration

package api

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func layoutInput(name, path string) *gen.LayoutInput {
	return &gen.LayoutInput{Name: name, Files: []gen.OutputFile{{Path: path, Format: gen.OutputFormat("pem"),
		Parts: []gen.OutputPart{gen.OutputPart("fullchain")}, Mode: "0644"}}}
}

func TestLayoutCRUD(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	res, err := f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: layoutInput("web", "/etc/ssl/web.pem")})
	if err != nil {
		t.Fatal(err)
	}
	l := res.(gen.CreateLayout201JSONResponse)
	if l.GrantCount != 0 || l.Files[0].Mode != "0644" {
		t.Fatalf("layout %+v", l)
	}
	_, err = f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: layoutInput("web", "/etc/ssl/other.pem")})
	wantStatus(t, err, 409)
	_, err = f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: layoutInput("rel", "etc/ssl/web.pem")})
	wantStatus(t, err, 422)
	_, err = f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: layoutInput("dots", "/etc/ssl/../web.pem")})
	wantStatus(t, err, 422)
	up, err := f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: l.Id, Body: layoutInput("web", "/etc/ssl/web2.pem")})
	if err != nil || up.(gen.UpdateLayout200JSONResponse).Files[0].Path != "/etc/ssl/web2.pem" {
		t.Fatalf("update %v %v", up, err)
	}
	list, _ := f.srv.ListLayouts(f.as("viewer"), gen.ListLayoutsRequestObject{OrgId: f.org})
	if len(list.(gen.ListLayouts200JSONResponse).Items) != 1 {
		t.Fatal("list")
	}
	_, err = f.srv.CreateLayout(f.as("viewer"), gen.CreateLayoutRequestObject{OrgId: f.org, Body: layoutInput("v", "/v.pem")})
	wantStatus(t, err, 403)
	if _, err := f.srv.DeleteLayout(op, gen.DeleteLayoutRequestObject{OrgId: f.org, Id: l.Id}); err != nil {
		t.Fatal(err)
	}
	var details string
	_ = f.pool.QueryRow(context.Background(), `SELECT details::text FROM audit_events WHERE action = 'layout.update'`).Scan(&details)
	if !strings.Contains(details, "web2.pem") || !strings.Contains(details, `"before"`) || f.auditCount(t, "layout.create") != 1 || f.auditCount(t, "layout.delete") != 1 {
		t.Fatalf("audit %s", details)
	}
}

func TestDeployTargetCRUD(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	in := func(cfg map[string]interface{}, typ string) *gen.DeployTargetInput {
		return &gen.DeployTargetInput{Name: "traefik", Type: gen.DeployTargetType(typ), Config: cfg}
	}
	res, err := f.srv.CreateDeployTarget(op, gen.CreateDeployTargetRequestObject{OrgId: f.org, Body: in(map[string]interface{}{"dir": "/etc/traefik/dynamic", "defaultCert": true}, "traefik")})
	if err != nil {
		t.Fatal(err)
	}
	dt := res.(gen.CreateDeployTarget201JSONResponse)
	if string(dt.RunsOn) != "agent" || dt.Config["dir"] != "/etc/traefik/dynamic" || dt.Config["defaultCert"] != true {
		t.Fatalf("target %+v", dt)
	}
	for _, bad := range []*gen.DeployTargetInput{
		in(map[string]interface{}{"dir": "/x"}, "nginx"),
		in(map[string]interface{}{"dir": "relative"}, "traefik"),
		in(map[string]interface{}{"dir": "/x", "nope": 1}, "traefik"),
	} {
		bad.Name = "other"
		_, err := f.srv.CreateDeployTarget(op, gen.CreateDeployTargetRequestObject{OrgId: f.org, Body: bad})
		wantStatus(t, err, 422)
	}
	up, err := f.srv.UpdateDeployTarget(op, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id, Body: in(map[string]interface{}{"dir": "/srv/traefik"}, "traefik")})
	if err != nil || up.(gen.UpdateDeployTarget200JSONResponse).Config["dir"] != "/srv/traefik" {
		t.Fatalf("update %v %v", up, err)
	}
	if _, err := f.srv.DeleteDeployTarget(op, gen.DeleteDeployTargetRequestObject{OrgId: f.org, Id: dt.Id}); err != nil {
		t.Fatal(err)
	}
	if f.auditCount(t, "deploy_target.create") != 1 || f.auditCount(t, "deploy_target.update") != 1 || f.auditCount(t, "deploy_target.delete") != 1 {
		t.Fatal("deploy target audit")
	}
}

func TestHookCRUD(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	sixty := 60
	_, err := f.srv.CreateHook(op, gen.CreateHookRequestObject{OrgId: f.org, Body: &gen.HookInput{Name: "reload", Phase: gen.HookPhase("post_deploy"), Argv: []string{"sh", "-c", "nginx -s reload"}}})
	wantStatus(t, err, 422)
	res, err := f.srv.CreateHook(op, gen.CreateHookRequestObject{OrgId: f.org, Body: &gen.HookInput{Name: "reload", Phase: gen.HookPhase("post_deploy"), Argv: []string{"/usr/sbin/nginx", "-s", "reload"}, TimeoutSeconds: &sixty}})
	if err != nil {
		t.Fatal(err)
	}
	h := res.(gen.CreateHook201JSONResponse)
	if h.TimeoutSeconds != 60 || len(h.Argv) != 3 {
		t.Fatalf("hook %+v", h)
	}
	if _, err := f.srv.DeleteHook(op, gen.DeleteHookRequestObject{OrgId: f.org, Id: h.Id}); err != nil {
		t.Fatal(err)
	}
	if f.auditCount(t, "hook.create") != 1 || f.auditCount(t, "hook.delete") != 1 {
		t.Fatal("hook audit")
	}
}

// Review Focus: deleting another org's layout, deploy target or hook by id
// must 404, never leak that org's grants (client/certificate names) in a 409.
func TestDeliveryDeleteIsOrgScoped(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	l, err := f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: layoutInput("web", "/etc/ssl/web.pem")})
	if err != nil {
		t.Fatal(err)
	}
	layout := l.(gen.CreateLayout201JSONResponse)
	dtRes, err := f.srv.CreateDeployTarget(op, gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "traefik", Type: gen.DeployTargetType("traefik"), Config: map[string]interface{}{"dir": "/etc/traefik/dynamic"}}})
	if err != nil {
		t.Fatal(err)
	}
	dt := dtRes.(gen.CreateDeployTarget201JSONResponse)
	sixty := 60
	hRes, err := f.srv.CreateHook(op, gen.CreateHookRequestObject{OrgId: f.org,
		Body: &gen.HookInput{Name: "reload", Phase: gen.HookPhase("post_deploy"), Argv: []string{"/bin/true"}, TimeoutSeconds: &sixty}})
	if err != nil {
		t.Fatal(err)
	}
	h := hRes.(gen.CreateHook201JSONResponse)

	orgB, err := f.q.CreateOrg(context.Background(), sqlcgen.CreateOrgParams{Slug: "org-b", Name: "Org B"})
	if err != nil {
		t.Fatal(err)
	}
	opB := authn.WithPrincipal(context.Background(), authn.Principal{Kind: authn.KindUser, UserID: uuid.New(),
		Roles: []string{authz.RoleOperator}, Bindings: []authn.Binding{{Role: authz.RoleOperator, OrgID: &orgB.ID}}, OrgIDs: []uuid.UUID{orgB.ID}})

	_, err = f.srv.DeleteLayout(opB, gen.DeleteLayoutRequestObject{OrgId: orgB.ID, Id: layout.Id})
	wantStatus(t, err, 404)
	_, err = f.srv.DeleteDeployTarget(opB, gen.DeleteDeployTargetRequestObject{OrgId: orgB.ID, Id: dt.Id})
	wantStatus(t, err, 404)
	_, err = f.srv.DeleteHook(opB, gen.DeleteHookRequestObject{OrgId: orgB.ID, Id: h.Id})
	wantStatus(t, err, 404)
}
