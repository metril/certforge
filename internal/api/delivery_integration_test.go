//go:build integration

package api

import (
	"context"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/api/gen"
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
