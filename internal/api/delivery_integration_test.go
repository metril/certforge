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
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/issuance"
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

func p12LayoutInput(password *string) *gen.LayoutInput {
	return &gen.LayoutInput{Name: "p12", Files: []gen.OutputFile{{Path: "/etc/ssl/web.p12", Format: gen.OutputFormat("p12"), Mode: "0600"}}, Password: password}
}

func strPtr(s string) *string { return &s }

// Review Focus: a layout's export password is write-only end to end: never
// returned by GET, never audited, and "__unchanged__" keeps the stored
// value (and the exact rendered bytes) across an update without it.
func TestLayoutPasswordWriteOnly(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")

	// A p12 file without a password is 422.
	_, err := f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: p12LayoutInput(nil)})
	wantStatus(t, err, 422)

	// "__unchanged__" on create is 422 (nothing stored yet to keep).
	_, err = f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: p12LayoutInput(strPtr(challenge.Unchanged))})
	wantStatus(t, err, 422)

	res, err := f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: p12LayoutInput(strPtr("hunter2222"))})
	if err != nil {
		t.Fatal(err)
	}
	l := res.(gen.CreateLayout201JSONResponse)
	if !l.PasswordSet {
		t.Fatalf("passwordSet = false, want true: %+v", l)
	}

	got, err := f.srv.GetLayout(op, gen.GetLayoutRequestObject{OrgId: f.org, Id: l.Id})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "hunter2222") {
		t.Fatal("GET response leaks the password")
	}
	var details string
	if err := f.pool.QueryRow(context.Background(), `SELECT details::text FROM audit_events WHERE action = 'layout.create'`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, "hunter2222") || !strings.Contains(details, `"passwordSet": true`) {
		t.Fatalf("audit does not carry passwordSet without the password: %s", details)
	}

	// Grant it to a client so the rendered p12 bytes (and their digest) can
	// be compared across an __unchanged__ update.
	c := f.activeClient(t, "web-p12")
	certID, _ := f.realCurrentCert(t, "web-p12-cert", true)
	gRes, err := f.srv.CreateGrant(f.as("admin"), gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.GrantInput{CertificateId: certID, Delivery: gen.GrantDelivery("pull"), LayoutId: &l.Id}})
	if err != nil {
		t.Fatal(err)
	}
	digest := gRes.(gen.CreateGrant201JSONResponse).Deployment.Expected[0].Sha256

	upRes, err := f.srv.UpdateLayout(f.as("admin"), gen.UpdateLayoutRequestObject{OrgId: f.org, Id: l.Id,
		Body: &gen.LayoutInput{Name: "p12", Files: p12LayoutInput(nil).Files, Password: strPtr(challenge.Unchanged)}})
	if err != nil {
		t.Fatal(err)
	}
	if !upRes.(gen.UpdateLayout200JSONResponse).PasswordSet {
		t.Fatal("passwordSet lost across an __unchanged__ update")
	}
	var updateDetails string
	if err := f.pool.QueryRow(context.Background(), `SELECT details::text FROM audit_events WHERE action = 'layout.update'`).Scan(&updateDetails); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(updateDetails, "hunter2222") || !strings.Contains(updateDetails, `"passwordSet": true`) {
		t.Fatalf("update audit leaks the password or drops passwordSet: %s", updateDetails)
	}
	list, err := f.srv.ListClientGrants(op, gen.ListClientGrantsRequestObject{OrgId: f.org, Id: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	items := list.(gen.ListClientGrants200JSONResponse).Items
	if len(items) != 1 || items[0].Deployment.Expected[0].Sha256 != digest {
		t.Fatalf("rendered bundle changed across an __unchanged__ update: %+v", items)
	}

	// An omitted password with a p12 file is still 422 (it would clear the
	// only password the file has).
	_, err = f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: l.Id,
		Body: &gen.LayoutInput{Name: "p12", Files: p12LayoutInput(nil).Files}})
	wantStatus(t, err, 422)
}

// TestUpdateLayoutKeylessGrant422 (4A final review, finding 1): a layout
// granted to a certificate whose current version has no key renders fine
// while the layout stays cert-only, but an update that makes it need a key
// (a key/combined part, a DER key, or a p12/jks file) must 422 naming the
// certificate rather than storing the change and letting the next Resync
// render fail opaquely with render.ErrNoKey (a 500 via mapAgentErr).
func TestUpdateLayoutKeylessGrant422(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	c := f.activeClient(t, "web-keyless-layout")

	leafDER, _, _ := realCert(t, "layout-keyless.example.test", 9301)
	body := pemCert(leafDER)
	res, err := f.srv.UploadCertificate(op, gen.UploadCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateUpload{Name: "layout-keyless", CertificatePem: &body}})
	if err != nil {
		t.Fatal(err)
	}
	certID := res.(gen.UploadCertificate201JSONResponse).Id

	certLayoutID := f.layout(t, "cert-only-layout", "/etc/ssl/layout-keyless.pem")
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &certLayoutID}}); err != nil {
		t.Fatal(err)
	}

	// The layout still renders fine against the keyless version.
	if _, err := f.srv.GetLayout(op, gen.GetLayoutRequestObject{OrgId: f.org, Id: certLayoutID}); err != nil {
		t.Fatal(err)
	}

	// PATCHing it to add a key part must 422, naming the certificate, not
	// store the change.
	keyUpdate := &gen.LayoutInput{Name: "cert-only-layout", Files: []gen.OutputFile{
		{Path: "/etc/ssl/layout-keyless.pem", Format: gen.OutputFormat("pem"), Parts: []gen.OutputPart{gen.OutputPart("fullchain")}, Mode: "0644"},
		{Path: "/etc/ssl/layout-keyless.key", Format: gen.OutputFormat("pem"), Parts: []gen.OutputPart{gen.OutputPart("key")}, Mode: "0600"},
	}}
	_, err = f.srv.UpdateLayout(f.as("admin"), gen.UpdateLayoutRequestObject{OrgId: f.org, Id: certLayoutID, Body: keyUpdate})
	wantStatus(t, err, 422)

	// The stored layout is unchanged (still cert-only).
	got, err := f.srv.GetLayout(op, gen.GetLayoutRequestObject{OrgId: f.org, Id: certLayoutID})
	if err != nil {
		t.Fatal(err)
	}
	if files := got.(gen.GetLayout200JSONResponse).Files; len(files) != 1 {
		t.Fatalf("layout files changed despite the 422: %+v", files)
	}
}

// Review Focus: extraCertificateIds is checked against the writing org and
// against having a current version, and a certificate a layout still lists
// cannot be deleted out from under it.
func TestLayoutExtraCertChecks(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	ctx := context.Background()

	noVersion, err := f.store.CreateCertificate(ctx, f.org, issuance.CertInput{Name: "no-version", CommonName: "no-version.example.test"})
	if err != nil {
		t.Fatal(err)
	}

	orgB, err := f.q.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: "org-extra", Name: "Org Extra"})
	if err != nil {
		t.Fatal(err)
	}
	var otherOrgCertID uuid.UUID
	if err := f.pool.QueryRow(ctx, `INSERT INTO certificates (org_id, name, common_name) VALUES ($1, 'other', 'other.example.test') RETURNING id`,
		orgB.ID).Scan(&otherOrgCertID); err != nil {
		t.Fatal(err)
	}

	extraLayoutInput := func(ids []uuid.UUID) *gen.LayoutInput {
		return &gen.LayoutInput{Name: "extra", Files: []gen.OutputFile{{Path: "/etc/ssl/extra.pem", Format: gen.OutputFormat("pem"),
			Parts: []gen.OutputPart{gen.OutputPart("extra")}, Mode: "0644"}}, ExtraCertificateIds: &ids}
	}

	_, err = f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: extraLayoutInput([]uuid.UUID{otherOrgCertID})})
	wantStatus(t, err, 422)

	_, err = f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: extraLayoutInput([]uuid.UUID{noVersion.ID})})
	wantStatus(t, err, 422)

	extraCertID, _ := f.realCurrentCert(t, "extra-cert", true)
	res, err := f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: extraLayoutInput([]uuid.UUID{extraCertID})})
	if err != nil {
		t.Fatal(err)
	}
	l := res.(gen.CreateLayout201JSONResponse)
	if len(l.ExtraCertificateIds) != 1 || l.ExtraCertificateIds[0] != extraCertID {
		t.Fatalf("extraCertificateIds = %v", l.ExtraCertificateIds)
	}

	_, err = f.srv.DeleteCertificate(op, gen.DeleteCertificateRequestObject{OrgId: f.org, Id: extraCertID})
	wantStatus(t, err, 409)
	var he *HTTPError
	if !errors.As(err, &he) || !strings.Contains(he.Detail, "extra") {
		t.Fatalf("409 detail does not name the layout: %v", err)
	}
}

func jksLayoutInput(password *string) *gen.LayoutInput {
	return &gen.LayoutInput{Name: "jks", Files: []gen.OutputFile{{Path: "/etc/ssl/web.jks", Format: gen.OutputFormat("jks"), Mode: "0600"}}, Password: password}
}

// Review Focus: a jks password must pass the exact same rule the renderer
// itself enforces (render.CheckJKSPassword: ASCII, at least 6 Unicode
// characters) before it is stored — not a looser byte-length check that
// lets a bad password through storage only to fail every later render
// (CreateGrant, Resync, OnVersion, the sweep).
func TestLayoutJKSPasswordASCII(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")

	_, err := f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: jksLayoutInput(strPtr("hüntér2"))})
	wantStatus(t, err, 422)

	res, err := f.srv.CreateLayout(op, gen.CreateLayoutRequestObject{OrgId: f.org, Body: jksLayoutInput(strPtr("hunter22"))})
	if err != nil {
		t.Fatal(err)
	}
	l := res.(gen.CreateLayout201JSONResponse)

	// Non-ASCII is also rejected on update, including when the file only
	// becomes jks in this same update (the stored password from a prior,
	// non-jks-validated write might not satisfy jks's rule).
	_, err = f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: l.Id, Body: jksLayoutInput(strPtr("hüntér2"))})
	wantStatus(t, err, 422)
}

// Making a layout key-bearing while a live grant uses it hands the key to
// that grant's agent, so it needs keys:export; an unused layout does not.
func TestUpdateLayoutKeyNeedsKeysExportWhenInUse(t *testing.T) {
	f := newAgentFixture(t)
	op, admin := f.as("operator"), f.as("admin")
	c := f.activeClient(t, "web-layout-key")
	certID, _ := f.currentCert(t, "web")
	layoutID := f.layout(t, "in-use", "/etc/ssl/in-use.pem")
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layoutID}}); err != nil {
		t.Fatal(err)
	}
	keyed := func(name, path string) *gen.LayoutInput {
		return &gen.LayoutInput{Name: name, Files: []gen.OutputFile{
			{Path: path, Format: gen.OutputFormat("pem"), Parts: []gen.OutputPart{gen.OutputPart("fullchain")}, Mode: "0644"},
			{Path: path + ".key", Format: gen.OutputFormat("pem"), Parts: []gen.OutputPart{gen.OutputPart("key")}, Mode: "0600"},
		}}
	}
	_, err := f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: layoutID, Body: keyed("in-use", "/etc/ssl/in-use.pem")})
	wantStatus(t, err, 403)
	got, err := f.srv.GetLayout(op, gen.GetLayoutRequestObject{OrgId: f.org, Id: layoutID})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(got.(gen.GetLayout200JSONResponse).Files); n != 1 {
		t.Fatalf("layout changed despite the 403: %d files", n)
	}
	if _, err := f.srv.UpdateLayout(admin, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: layoutID, Body: keyed("in-use", "/etc/ssl/in-use.pem")}); err != nil {
		t.Fatalf("admin key-bearing update: %v", err)
	}

	unused := f.layout(t, "unused", "/etc/ssl/unused.pem")
	if _, err := f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: unused, Body: keyed("unused", "/etc/ssl/unused.pem")}); err != nil {
		t.Fatalf("operator update of an unused layout: %v", err)
	}
}
