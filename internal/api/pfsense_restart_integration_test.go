//go:build integration

package api

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/deploy"
)

func TestServerGrantPfSenseRestartOptions(t *testing.T) {
	f := newAgentFixture(t)
	vaultT, _ := f.serverTarget(t, "vault", nil)
	f.srv.d.Targets.Register(deploy.PfSense{})
	pfT := f.pfTarget(t, "https://fw.example.net")
	certID, _ := f.currentCert(t, "web")
	admin := f.as("admin")
	sel := map[string]interface{}{"pfsenseRestart": map[string]interface{}{"mode": "selected", "services": []interface{}{"webgui", "openvpn:server:1"}}}
	create := func(target uuid.UUID, opts map[string]interface{}) (gen.Grant, error) {
		res, err := f.srv.CreateServerGrant(admin, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: target,
			Body: &gen.ServerGrantInput{CertificateId: certID, TargetOptions: &opts}})
		if err != nil {
			return gen.Grant{}, err
		}
		return gen.Grant(res.(gen.CreateServerGrant201JSONResponse)), nil
	}
	for _, bad := range []map[string]interface{}{
		{"pfsenseRestart": map[string]interface{}{"mode": "some"}},
		{"pfsenseRestart": map[string]interface{}{"mode": "selected", "services": []interface{}{"x;y"}}},
		{"pfsenseRestart": map[string]interface{}{"mode": "selected"}},
		{"other": true},
	} {
		if _, err := create(pfT, bad); problemStatus(err) != 422 {
			t.Fatalf("accepted %v: %v", bad, err)
		}
	}
	if _, err := create(vaultT, sel); problemStatus(err) != 422 {
		t.Fatalf("options on a vault target: %v", err)
	}
	g, err := create(pfT, sel)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(g.TargetOptions); string(b) != `{"pfsenseRestart":{"mode":"selected","services":["webgui","openvpn:server:1"]}}` {
		t.Fatalf("create returned %s", b)
	}
	list, err := f.srv.ListTargetGrants(admin, gen.ListTargetGrantsRequestObject{OrgId: f.org, Id: pfT})
	if err != nil {
		t.Fatal(err)
	}
	if got := list.(gen.ListTargetGrants200JSONResponse); len(got) != 1 || got[0].TargetOptions["pfsenseRestart"] == nil {
		t.Fatalf("list = %+v", got)
	}
	update := func(opts map[string]interface{}) (gen.Grant, error) {
		res, err := f.srv.UpdateGrant(admin, gen.UpdateGrantRequestObject{OrgId: f.org, Id: g.Id,
			Body: &gen.GrantUpdate{Delivery: "push", HookIds: []uuid.UUID{}, TargetOptions: opts}})
		if err != nil {
			return gen.Grant{}, err
		}
		return gen.Grant(res.(gen.UpdateGrant200JSONResponse)), nil
	}
	if _, err := update(map[string]interface{}{"pfsenseRestart": map[string]interface{}{"mode": "all", "services": []interface{}{"ipsec"}}}); problemStatus(err) != 422 {
		t.Fatalf("all with services: %v", err)
	}
	u, err := update(map[string]interface{}{"pfsenseRestart": map[string]interface{}{"mode": "none"}})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(u.TargetOptions); string(b) != `{"pfsenseRestart":{"mode":"none"}}` {
		t.Fatalf("update returned %s", b)
	}
	if u, err = update(map[string]interface{}{}); err != nil || len(u.TargetOptions) != 0 {
		t.Fatalf("clearing: %v %v", u.TargetOptions, err)
	}
}
