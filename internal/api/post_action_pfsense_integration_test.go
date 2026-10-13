//go:build integration

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/deploy"
)

// pfTarget stores a pfsense deploy target pointing at url, with the password sealed.
func (f *agentFixture) pfTarget(t *testing.T, url string) uuid.UUID {
	t.Helper()
	pub, _ := json.Marshal(map[string]any{"url": url + "/api", "username": "admin", "timeoutSeconds": 5})
	sealed, err := f.box.Seal(context.Background(), []byte(`{"password":"pw"}`))
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO deploy_targets (org_id, name, type, runs_on, config, secret_cfg) VALUES ($1, $2, 'pfsense', 'server', $3, $4) RETURNING id`,
		f.org, "pf-"+uuid.NewString()[:8], pub, sealed).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestServerGrantPfSensePostAction(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	targetID, _ := f.serverTarget(t, "vault", nil)
	certID, _ := f.currentCert(t, "web")
	sshT := f.sshTargetIn(t, f.org, "ssh")
	pfT := f.pfTarget(t, "https://fw.example.net")
	kind := func(k gen.PostActionKind) *gen.PostActionKind { return &k }
	create := func(c uuid.UUID, pa *gen.PostAction) (gen.CreateServerGrant201JSONResponse, error) {
		res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
			Body: &gen.ServerGrantInput{CertificateId: c, PostAction: pa}})
		if err != nil {
			return gen.CreateServerGrant201JSONResponse{}, err
		}
		return res.(gen.CreateServerGrant201JSONResponse), nil
	}
	// The target type must match the kind.
	if _, err := create(certID, &gen.PostAction{Kind: kind("pfsense"), TargetId: sshT, Command: "true"}); problemStatus(err) != 422 {
		t.Fatalf("pfsense kind on ssh target: %v", err)
	}
	if _, err := create(certID, &gen.PostAction{TargetId: pfT, Command: "true"}); problemStatus(err) != 422 {
		t.Fatalf("ssh kind on pfsense target: %v", err)
	}
	g, err := create(certID, &gen.PostAction{Kind: kind("pfsense"), TargetId: pfT, Command: "/etc/rc.restart_webgui"})
	if err != nil {
		t.Fatal(err)
	}
	if g.PostAction == nil || g.PostAction.Kind == nil || *g.PostAction.Kind != "pfsense" || g.PostAction.TargetId != pfT {
		t.Fatalf("postAction = %+v", g.PostAction)
	}
	if _, err := f.srv.DeleteDeployTarget(f.as("admin"), gen.DeleteDeployTargetRequestObject{OrgId: f.org, Id: pfT}); problemStatus(err) != 409 {
		t.Fatalf("delete in-use pfsense target: %v", err)
	}
	// A row saved before kinds existed reads as ssh and still blocks deleting its target.
	cert2, _ := f.currentCert(t, "api")
	g2, err := create(cert2, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"sshTargetId":"` + sshT.String() + `","command":"reload","timeoutSeconds":30}`
	if _, err := f.pool.Exec(context.Background(), `UPDATE client_cert_grants SET post_action = $2::jsonb WHERE id = $1`, g2.Id, legacy); err != nil {
		t.Fatal(err)
	}
	got, err := f.srv.serverGrantByID(context.Background(), f.org, g2.Id)
	if err != nil {
		t.Fatal(err)
	}
	if got.PostAction == nil || got.PostAction.Kind == nil || *got.PostAction.Kind != "ssh" || got.PostAction.TargetId != sshT || got.PostAction.Command != "reload" {
		t.Fatalf("legacy postAction = %+v", got.PostAction)
	}
	if _, err := f.srv.DeleteDeployTarget(f.as("admin"), gen.DeleteDeployTargetRequestObject{OrgId: f.org, Id: sshT}); problemStatus(err) != 409 {
		t.Fatalf("delete legacy-referenced ssh target: %v", err)
	}
}

func TestGrantPfSenseUsage(t *testing.T) {
	f := newAgentFixture(t)
	fw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			_, _ = io.WriteString(w, `{"token":"tok"}`)
		case "/api/mim/devices":
			_, _ = io.WriteString(w, `{"devices":[]}`)
		case "/api/system/certificates":
			_, _ = io.WriteString(w, `[{"refid":"abc123","descr":"web"}]`)
		case "/api/diag/cmd/php":
			_, _ = io.WriteString(w, `{"response":"CFJSON:{\"webgui\":true,\"services\":[{\"name\":\"ipsec\"}],\"packages\":[]}"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer fw.Close()
	vaultT, _ := f.serverTarget(t, "vault", nil)
	f.srv.d.Targets.Register(deploy.PfSense{})
	pfT := f.pfTarget(t, fw.URL)
	certID, _ := f.currentCert(t, "web")
	otherCert, _ := f.currentCert(t, "other")
	grant := func(c uuid.UUID, target uuid.UUID) uuid.UUID {
		res, err := f.srv.CreateServerGrant(f.as("admin"), gen.CreateServerGrantRequestObject{OrgId: f.org, Id: target,
			Body: &gen.ServerGrantInput{CertificateId: c}})
		if err != nil {
			t.Fatal(err)
		}
		return res.(gen.CreateServerGrant201JSONResponse).Id
	}
	usage := func(id uuid.UUID) (gen.PfSenseUsage, error) {
		res, err := f.srv.GetGrantPfSenseUsage(f.as("viewer"), gen.GetGrantPfSenseUsageRequestObject{OrgId: f.org, Id: id})
		if err != nil {
			return gen.PfSenseUsage{}, err
		}
		return gen.PfSenseUsage(res.(gen.GetGrantPfSenseUsage200JSONResponse)), nil
	}
	u, err := usage(grant(certID, pfT))
	if err != nil || u.Refid == nil || *u.Refid != "abc123" || len(u.Services) != 2 || u.Services[0] != (gen.PfSenseService{Key: "webgui", Label: "WebGUI"}) || u.Services[1] != (gen.PfSenseService{Key: "ipsec", Label: "IPsec"}) {
		t.Fatalf("usage = %+v err=%v", u, err)
	}
	u, err = usage(grant(otherCert, pfT)) // certificate not on the firewall
	if err != nil || u.Refid != nil || len(u.Services) != 0 {
		t.Fatalf("absent = %+v err=%v", u, err)
	}
	if _, err := usage(grant(certID, vaultT)); problemStatus(err) != 422 {
		t.Fatalf("non-pfsense target: %v", err)
	}
	if _, err := usage(uuid.New()); problemStatus(err) != 404 {
		t.Fatalf("unknown grant: %v", err)
	}
}

func TestServerGrantPiKVMPostAction(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	targetID, _ := f.serverTarget(t, "vault", nil)
	certID, _ := f.currentCert(t, "web")
	pk := f.sshTargetIn(t, f.org, "pikvm")
	if _, err := f.pool.Exec(context.Background(), `UPDATE deploy_targets SET type = 'pikvm' WHERE id = $1`, pk); err != nil {
		t.Fatal(err)
	}
	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID, PostAction: &gen.PostAction{TargetId: pk, Command: "true"}}})
	if err != nil {
		t.Fatalf("ssh post action on a pikvm target: %v", err)
	}
	_ = res.(gen.CreateServerGrant201JSONResponse)
}
