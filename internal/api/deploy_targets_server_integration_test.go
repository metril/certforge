//go:build integration

package api

import (
	"testing"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/deploy"
	"github.com/metril/certforge/internal/meta"
)

// TestServerTargetCRUD covers a vault-kv deploy target's create/update: its
// runsOn is always derived as "server" (there is no runsOn field on
// DeployTargetInput for a caller to mismatch), defaults are filled into
// the stored config, an invalid config is 422, and includeKey needs
// keys:export on create and update, whether it is turning true or simply
// staying true (batch-5 review; controller ruling) — TestServerTargetIncludeKeyRequiresKeysExport
// covers that in detail, this test only confirms an operator (no
// keys:export) can still create/update/delete a target that never sets it.
func TestServerTargetCRUD(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")

	res, err := f.srv.CreateDeployTarget(op, gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "vault", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{}}})
	if err != nil {
		t.Fatal(err)
	}
	dt := res.(gen.CreateDeployTarget201JSONResponse)
	if string(dt.RunsOn) != "server" {
		t.Fatalf("runsOn = %s, want server", dt.RunsOn)
	}
	if dt.Config["mount"] != "secret" || dt.Config["path"] != "certforge/{org}/{name}" {
		t.Fatalf("defaults not filled: %+v", dt.Config)
	}
	if v, ok := dt.Config["includeKey"]; ok && v != false {
		t.Fatalf("includeKey default = %+v, want false or omitted", v)
	}
	keys, ok := dt.Config["keys"].(map[string]interface{})
	if !ok || keys["fullchain"] != "fullchain.pem" || keys["key"] != "privkey.pem" {
		t.Fatalf("keys defaults not filled: %+v", dt.Config)
	}

	// includeKey:true needs keys:export, which admin holds (a global-only
	// action) and operator does not.
	keyRes, err := f.srv.CreateDeployTarget(f.as("admin"), gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "vault-key", Type: gen.DeployTargetType("vault-kv"),
			Config: map[string]interface{}{"includeKey": true}}})
	if err != nil {
		t.Fatal(err)
	}
	if keyRes.(gen.CreateDeployTarget201JSONResponse).Config["includeKey"] != true {
		t.Fatal("includeKey not stored")
	}

	for _, bad := range []map[string]interface{}{
		{"mount": "??"},
		{"path": "/etc/passwd"},
		{"path": "{unknown}"},
		{"nope": "field"},
	} {
		_, err := f.srv.CreateDeployTarget(op, gen.CreateDeployTargetRequestObject{OrgId: f.org,
			Body: &gen.DeployTargetInput{Name: "bad", Type: gen.DeployTargetType("vault-kv"), Config: bad}})
		wantStatus(t, err, 422)
	}

	// An unregistered type is still 422 (unchanged from before this task).
	_, err = f.srv.CreateDeployTarget(op, gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "nope", Type: gen.DeployTargetType("nginx"), Config: map[string]interface{}{}}})
	wantStatus(t, err, 422)

	up, err := f.srv.UpdateDeployTarget(op, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id,
		Body: &gen.DeployTargetInput{Name: "vault", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"mount": "kv2"}}})
	if err != nil {
		t.Fatal(err)
	}
	updated := up.(gen.UpdateDeployTarget200JSONResponse)
	if string(updated.RunsOn) != "server" || updated.Config["mount"] != "kv2" {
		t.Fatalf("update = %+v", updated)
	}

	// type is immutable.
	_, err = f.srv.UpdateDeployTarget(op, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id,
		Body: &gen.DeployTargetInput{Name: "vault", Type: gen.DeployTargetType("traefik"), Config: map[string]interface{}{"dir": "/x"}}})
	wantStatus(t, err, 422)

	if _, err := f.srv.DeleteDeployTarget(op, gen.DeleteDeployTargetRequestObject{OrgId: f.org, Id: dt.Id}); err != nil {
		t.Fatal(err)
	}
	if f.auditCount(t, "deploy_target.create") != 2 || f.auditCount(t, "deploy_target.update") != 1 || f.auditCount(t, "deploy_target.delete") != 1 {
		t.Fatal("deploy target audit")
	}
}

// TestServerTargetIncludeKeyRequiresKeysExport covers the batch-5 review
// fix: includeKey:true needs keys:export on create, on an update that
// turns it true, and on an update that leaves it true — delivery:write
// alone (what operator holds) is never enough, since the next deploy to a
// target with includeKey would write a private key to Vault.
func TestServerTargetIncludeKeyRequiresKeysExport(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	admin := f.as("admin")

	// Create with includeKey:true: 403 for operator, 201 for admin.
	_, err := f.srv.CreateDeployTarget(op, gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "v1", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"includeKey": true}}})
	wantStatus(t, err, 403)
	res, err := f.srv.CreateDeployTarget(admin, gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "v1", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"includeKey": true}}})
	if err != nil {
		t.Fatal(err)
	}
	keyTarget := res.(gen.CreateDeployTarget201JSONResponse).Id

	// Update that leaves includeKey true (unchanged, still present in the
	// body): still gated, not just "turning" true.
	_, err = f.srv.UpdateDeployTarget(op, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: keyTarget,
		Body: &gen.DeployTargetInput{Name: "v1", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"includeKey": true, "mount": "kv2"}}})
	wantStatus(t, err, 403)
	up, err := f.srv.UpdateDeployTarget(admin, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: keyTarget,
		Body: &gen.DeployTargetInput{Name: "v1", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"includeKey": true, "mount": "kv2"}}})
	if err != nil || up.(gen.UpdateDeployTarget200JSONResponse).Config["mount"] != "kv2" {
		t.Fatalf("admin update stays gated correctly: %v %v", up, err)
	}

	// A target created without includeKey, operator can create freely...
	res, err = f.srv.CreateDeployTarget(op, gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "v2", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{}}})
	if err != nil {
		t.Fatal(err)
	}
	plainTarget := res.(gen.CreateDeployTarget201JSONResponse).Id

	// ...but an update turning it true is 403 for operator, 200 for admin.
	_, err = f.srv.UpdateDeployTarget(op, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: plainTarget,
		Body: &gen.DeployTargetInput{Name: "v2", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"includeKey": true}}})
	wantStatus(t, err, 403)
	up, err = f.srv.UpdateDeployTarget(admin, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: plainTarget,
		Body: &gen.DeployTargetInput{Name: "v2", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"includeKey": true}}})
	if err != nil || up.(gen.UpdateDeployTarget200JSONResponse).Config["includeKey"] != true {
		t.Fatalf("admin turning includeKey true: %v %v", up, err)
	}

	// An update that turns includeKey back to false needs no export
	// permission at all.
	if _, err := f.srv.UpdateDeployTarget(op, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: plainTarget,
		Body: &gen.DeployTargetInput{Name: "v2", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"includeKey": false}}}); err != nil {
		t.Fatalf("operator turning includeKey false: %v", err)
	}
}

// TestMetaSchemasVaultKV covers GET /meta/schemas listing vault-kv under
// deployTargets, with its display name.
func TestMetaSchemasVaultKV(t *testing.T) {
	f := newAPIFixture(t)
	f.srv.d.Meta = meta.NewRegistry()
	reg := deploy.NewRegistry()
	reg.Register("Vault KV (runs on server)", deploy.VaultKV{})
	deploy.AddToMeta(reg, f.srv.d.Meta)

	res, err := f.srv.GetMetaSchemas(f.as("viewer"), gen.GetMetaSchemasRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	out := res.(gen.GetMetaSchemas200JSONResponse)
	if len(out.DeployTargets) != 1 || out.DeployTargets[0].Code != "vault-kv" || out.DeployTargets[0].Name != "Vault KV (runs on server)" {
		t.Fatalf("deployTargets = %+v", out.DeployTargets)
	}
}
