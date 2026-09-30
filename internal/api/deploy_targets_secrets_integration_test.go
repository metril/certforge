//go:build integration

package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/deploy"
	"github.com/metril/certforge/internal/meta"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/targetstest"
)

// registerTestSecret adds a targetstest.Secret target under code into f's
// own registry (never a product registry: TestProductRegistriesHaveNoTestTypes
// and TestAgentImports both guard against that; this fixture's registry is
// its own instance, built fresh per test by newAPIFixture).
func (f *agentFixture) registerTestSecret(code string, mode targets.Mode, policy targets.KeyPolicy) *targetstest.Secret {
	sec := &targetstest.Secret{Code: code, Mode: mode, Policy: policy}
	f.srv.d.Targets.Register(sec)
	return sec
}

func createTestSecret(t *testing.T, f *agentFixture, name string, runsOn *gen.RunsOn, cfg map[string]interface{}) (gen.DeployTarget, error) {
	t.Helper()
	caller := f.as("operator")
	if v, _ := cfg["includeKey"].(bool); v {
		caller = f.as("admin")
	}
	res, err := f.srv.CreateDeployTarget(caller, gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: name, Type: gen.DeployTargetType("test-secret"), RunsOn: runsOn, Config: cfg}})
	if err != nil {
		return gen.DeployTarget{}, err
	}
	return gen.DeployTarget(res.(gen.CreateDeployTarget201JSONResponse)), nil
}

// TestTargetReadNeverReturnsSecrets covers GET/list on a test-secret target:
// the token never appears in config, and storedSecrets names it.
func TestTargetReadNeverReturnsSecrets(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Optional)

	dt, err := createTestSecret(t, f, "sec", ptr(gen.RunsOn("server")),
		map[string]interface{}{"url": "https://example.test", "token": "sekrit-token-value"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dt.Config["token"]; ok {
		t.Fatalf("config leaks token: %+v", dt.Config)
	}
	if len(dt.StoredSecrets) != 1 || dt.StoredSecrets[0] != "token" {
		t.Fatalf("storedSecrets = %+v, want [token]", dt.StoredSecrets)
	}

	get, err := f.srv.GetDeployTarget(f.as("operator"), gen.GetDeployTargetRequestObject{OrgId: f.org, Id: dt.Id})
	if err != nil {
		t.Fatal(err)
	}
	got := gen.DeployTarget(get.(gen.GetDeployTarget200JSONResponse))
	if _, ok := got.Config["token"]; ok {
		t.Fatalf("get config leaks token: %+v", got.Config)
	}
	if len(got.StoredSecrets) != 1 || got.StoredSecrets[0] != "token" {
		t.Fatalf("get storedSecrets = %+v, want [token]", got.StoredSecrets)
	}

	list, err := f.srv.ListDeployTargets(f.as("operator"), gen.ListDeployTargetsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	items := list.(gen.ListDeployTargets200JSONResponse).Items
	if len(items) != 1 {
		t.Fatalf("list = %+v", items)
	}
	if _, ok := items[0].Config["token"]; ok {
		t.Fatalf("list config leaks token: %+v", items[0].Config)
	}
	body, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "sekrit-token-value") {
		t.Fatal("list response leaks token value")
	}
}

// TestTargetUnchangedKeepsSecret covers omitting a secret field (and
// sending __unchanged__ explicitly) on update: both keep the stored value.
func TestTargetUnchangedKeepsSecret(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Optional)

	dt, err := createTestSecret(t, f, "sec", ptr(gen.RunsOn("server")),
		map[string]interface{}{"url": "https://example.test", "token": "t1", "note": "n1"})
	if err != nil {
		t.Fatal(err)
	}

	// Omitted: both secrets stay stored.
	up1, err := f.srv.UpdateDeployTarget(f.as("operator"), gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"), RunsOn: ptr(gen.RunsOn("server")),
			Config: map[string]interface{}{"url": "https://example.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	got1 := gen.DeployTarget(up1.(gen.UpdateDeployTarget200JSONResponse))
	if len(got1.StoredSecrets) != 2 || got1.StoredSecrets[0] != "note" || got1.StoredSecrets[1] != "token" {
		t.Fatalf("storedSecrets after omitted update = %+v, want [note token]", got1.StoredSecrets)
	}

	// Explicit __unchanged__: same result.
	up2, err := f.srv.UpdateDeployTarget(f.as("operator"), gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"), RunsOn: ptr(gen.RunsOn("server")),
			Config: map[string]interface{}{"url": "https://example.test", "token": targets.Unchanged, "note": targets.Unchanged}}})
	if err != nil {
		t.Fatal(err)
	}
	got2 := gen.DeployTarget(up2.(gen.UpdateDeployTarget200JSONResponse))
	if len(got2.StoredSecrets) != 2 || got2.StoredSecrets[0] != "note" || got2.StoredSecrets[1] != "token" {
		t.Fatalf("storedSecrets after __unchanged__ update = %+v, want [note token]", got2.StoredSecrets)
	}
}

// TestTargetUnchangedWithoutStored422 covers __unchanged__ sent for a
// secret that was never stored (note was never set on create).
func TestTargetUnchangedWithoutStored422(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Optional)

	dt, err := createTestSecret(t, f, "sec", ptr(gen.RunsOn("server")),
		map[string]interface{}{"url": "https://example.test", "token": "t1"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.srv.UpdateDeployTarget(f.as("operator"), gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"), RunsOn: ptr(gen.RunsOn("server")),
			Config: map[string]interface{}{"url": "https://example.test", "note": targets.Unchanged}}})
	wantStatus(t, err, 422)
	if !strings.Contains(err.Error(), "note") || !strings.Contains(err.Error(), "no stored value") {
		t.Fatalf("error = %v, want mention of note having no stored value", err)
	}
}

// TestTargetClearOptionalSecret covers clearing an optional secret with ""
// (allowed) and a required one (422: the type's own Parse still requires it).
func TestTargetClearOptionalSecret(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Optional)

	dt, err := createTestSecret(t, f, "sec", ptr(gen.RunsOn("server")),
		map[string]interface{}{"url": "https://example.test", "token": "t1", "note": "n1"})
	if err != nil {
		t.Fatal(err)
	}

	up, err := f.srv.UpdateDeployTarget(f.as("operator"), gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"), RunsOn: ptr(gen.RunsOn("server")),
			Config: map[string]interface{}{"url": "https://example.test", "token": targets.Unchanged, "note": ""}}})
	if err != nil {
		t.Fatal(err)
	}
	got := gen.DeployTarget(up.(gen.UpdateDeployTarget200JSONResponse))
	if len(got.StoredSecrets) != 1 || got.StoredSecrets[0] != "token" {
		t.Fatalf("storedSecrets after clearing note = %+v, want [token]", got.StoredSecrets)
	}

	_, err = f.srv.UpdateDeployTarget(f.as("operator"), gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"), RunsOn: ptr(gen.RunsOn("server")),
			Config: map[string]interface{}{"url": "https://example.test", "token": ""}}})
	wantStatus(t, err, 422)
}

// TestTargetReentryOnURLChange covers a URL change while a secret is kept
// (reused): the update is refused until the secret is re-entered too.
func TestTargetReentryOnURLChange(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Optional)

	dt, err := createTestSecret(t, f, "sec", ptr(gen.RunsOn("server")),
		map[string]interface{}{"url": "https://a.example.test", "token": "t1"})
	if err != nil {
		t.Fatal(err)
	}

	// url changes, token omitted (reused): 422.
	_, err = f.srv.UpdateDeployTarget(f.as("operator"), gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"), RunsOn: ptr(gen.RunsOn("server")),
			Config: map[string]interface{}{"url": "https://b.example.test"}}})
	wantStatus(t, err, 422)
	if !strings.Contains(err.Error(), "re-enter the secret") {
		t.Fatalf("error = %v, want re-enter the secret", err)
	}

	// url changes, token re-entered: fine.
	up, err := f.srv.UpdateDeployTarget(f.as("operator"), gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"), RunsOn: ptr(gen.RunsOn("server")),
			Config: map[string]interface{}{"url": "https://b.example.test", "token": "t2"}}})
	if err != nil {
		t.Fatal(err)
	}
	got := gen.DeployTarget(up.(gen.UpdateDeployTarget200JSONResponse))
	if got.Config["url"] != "https://b.example.test" {
		t.Fatalf("url not updated: %+v", got.Config)
	}
}

// TestRunsOnImmutable covers a create/update runsOn cycle on an Either
// type: chosen at create, refused to change on update.
func TestRunsOnImmutable(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Optional)

	dt, err := createTestSecret(t, f, "sec", ptr(gen.RunsOn("server")),
		map[string]interface{}{"url": "https://example.test", "token": "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if string(dt.RunsOn) != "server" {
		t.Fatalf("runsOn = %s, want server", dt.RunsOn)
	}

	_, err = f.srv.UpdateDeployTarget(f.as("operator"), gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"), RunsOn: ptr(gen.RunsOn("agent")),
			Config: map[string]interface{}{"url": "https://example.test", "token": "t1"}}})
	wantStatus(t, err, 422)

	// Sending the same runsOn (or omitting it) is fine.
	up, err := f.srv.UpdateDeployTarget(f.as("operator"), gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: dt.Id,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"),
			Config: map[string]interface{}{"url": "https://example.test", "token": "t1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if string(gen.DeployTarget(up.(gen.UpdateDeployTarget200JSONResponse)).RunsOn) != "server" {
		t.Fatal("runsOn changed on an update that omitted it")
	}
}

// TestRunsOnForcedMismatch422 covers a forced-mode type (traefik: agent)
// given a mismatched runsOn on create.
func TestRunsOnForcedMismatch422(t *testing.T) {
	f := newAgentFixture(t)
	_, err := f.srv.CreateDeployTarget(f.as("operator"), gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "tk", Type: gen.DeployTargetType("traefik"), RunsOn: ptr(gen.RunsOn("server")),
			Config: map[string]interface{}{"dir": "/etc/traefik/dynamic"}}})
	wantStatus(t, err, 422)
	if !strings.Contains(err.Error(), "runs on agent") {
		t.Fatalf("error = %v, want mention of runs on agent", err)
	}
}

// TestEitherRequiresRunsOn covers an Either type given no runsOn on create.
func TestEitherRequiresRunsOn(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Optional)

	_, err := f.srv.CreateDeployTarget(f.as("operator"), gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"),
			Config: map[string]interface{}{"url": "https://example.test", "token": "t1"}}})
	wantStatus(t, err, 422)
	if !strings.Contains(err.Error(), "choose where this target runs") {
		t.Fatalf("error = %v, want choose where this target runs", err)
	}
}

// TestTargetKeysExportOnUpdate covers keys:export gating on an update that
// needs the certificate's private key, generalized beyond vault-kv: a
// server-run test-secret (Optional key policy) with includeKey needs it
// too, not only vault-kv's own includeKey field.
func TestTargetKeysExportOnUpdate(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Optional)
	op := f.as("operator")

	// vault-kv: covered in detail by TestServerTargetIncludeKeyRequiresKeysExport;
	// this only confirms the update path is still gated.
	vk, err := f.srv.CreateDeployTarget(op, gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: "vk", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{}}})
	if err != nil {
		t.Fatal(err)
	}
	vkID := vk.(gen.CreateDeployTarget201JSONResponse).Id
	_, err = f.srv.UpdateDeployTarget(op, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: vkID,
		Body: &gen.DeployTargetInput{Name: "vk", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"includeKey": true}}})
	wantStatus(t, err, 403)

	// A server-run test-secret target, created without includeKey (no gate
	// needed), then updated to includeKey:true (needs keys:export).
	sec, err := createTestSecret(t, f, "sec", ptr(gen.RunsOn("server")), map[string]interface{}{"url": "https://example.test", "token": "t1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.srv.UpdateDeployTarget(op, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: sec.Id,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"),
			Config: map[string]interface{}{"url": "https://example.test", "token": "t1", "includeKey": true}}})
	wantStatus(t, err, 403)

	admin := f.as("admin")
	up, err := f.srv.UpdateDeployTarget(admin, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: sec.Id,
		Body: &gen.DeployTargetInput{Name: "sec", Type: gen.DeployTargetType("test-secret"),
			Config: map[string]interface{}{"url": "https://example.test", "token": "t1", "includeKey": true}}})
	if err != nil || gen.DeployTarget(up.(gen.UpdateDeployTarget200JSONResponse)).Config["includeKey"] != true {
		t.Fatalf("admin update: %v %v", up, err)
	}
}

// TestServerTargetURLPolicy covers the URL policy at create time: a
// server-run target rejects loopback and cloud-metadata addresses (the
// org's allowLoopbackUrls setting defaults to false in this fixture); an
// agent-run target allows loopback (its own network is the operator's to
// reach) but still rejects the cloud-metadata address.
func TestServerTargetURLPolicy(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Optional)

	// batch 2 review, finding 2: the problem body names the field, never
	// echoes the URL — a userinfo or query-string token in the rejected URL
	// (this one carries both) must never reach the response.
	for _, u := range []string{"http://127.0.0.1:8080", "http://169.254.169.254/latest/meta-data",
		"http://user:leak-me@169.254.169.254/path?token=leak-me-too"} {
		_, err := createTestSecret(t, f, "sec", ptr(gen.RunsOn("server")), map[string]interface{}{"url": u, "token": "t1"})
		wantStatus(t, err, 422)
		if !strings.Contains(err.Error(), "address not allowed") {
			t.Fatalf("url %s: error = %v, want address not allowed", u, err)
		}
		if strings.Contains(err.Error(), u) || strings.Contains(err.Error(), "leak-me") {
			t.Fatalf("url %s: error = %v, the rejected URL must never be echoed back", u, err)
		}
	}

	if _, err := createTestSecret(t, f, "loopback-ok", ptr(gen.RunsOn("agent")),
		map[string]interface{}{"url": "http://127.0.0.1:8080", "token": "t1"}); err != nil {
		t.Fatalf("agent target with loopback url: %v", err)
	}
	_, err := createTestSecret(t, f, "metadata-blocked", ptr(gen.RunsOn("agent")),
		map[string]interface{}{"url": "http://169.254.169.254/latest/meta-data", "token": "t1"})
	wantStatus(t, err, 422)
}

// TestTargetAuditHasNoConfig covers the audit details shape (Shared
// contracts Audit row): targetId, name, type, runsOn only — never config,
// so a secret (or even the public config) can never reach an audit record.
func TestTargetAuditHasNoConfig(t *testing.T) {
	f := newAgentFixture(t)
	f.registerTestSecret("test-secret", targets.Either, targets.Optional)

	dt, err := createTestSecret(t, f, "sec", ptr(gen.RunsOn("server")),
		map[string]interface{}{"url": "https://example.test", "token": "sekrit-audit-value"})
	if err != nil {
		t.Fatal(err)
	}
	details := f.lastAuditDetails(t, "deploy_target.create", dt.Id.String())
	if strings.Contains(details, "sekrit-audit-value") {
		t.Fatalf("audit leaks secret: %s", details)
	}
	if strings.Contains(details, "config") || strings.Contains(details, "url") {
		t.Fatalf("audit logs config: %s", details)
	}
	for _, want := range []string{"targetId", "name", "type", "runsOn"} {
		if !strings.Contains(details, want) {
			t.Fatalf("audit details missing %s: %s", want, details)
		}
	}
}

// TestMetaSchemasCarryRunsOn covers GET /meta/schemas listing runsOn/keyPolicy
// for the product deploy target types (Deviations R8/R9).
func TestMetaSchemasCarryRunsOn(t *testing.T) {
	f := newAPIFixture(t)
	f.srv.d.Meta = meta.NewRegistry()
	reg := targets.NewRegistry()
	targets.RegisterBuiltins(reg)
	reg.Register(deploy.VaultKV{})
	targets.AddToMeta(reg, f.srv.d.Meta)

	res, err := f.srv.GetMetaSchemas(f.as("viewer"), gen.GetMetaSchemasRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	out := res.(gen.GetMetaSchemas200JSONResponse)
	found := map[string]gen.SchemaEntry{}
	for _, e := range out.DeployTargets {
		found[e.Code] = e
	}
	vk, ok := found["vault-kv"]
	if !ok || vk.RunsOn == nil || string(*vk.RunsOn) != "server" || vk.KeyPolicy == nil || string(*vk.KeyPolicy) != "optional" {
		t.Fatalf("vault-kv entry = %+v", vk)
	}
	tk, ok := found["traefik"]
	if !ok || tk.RunsOn == nil || string(*tk.RunsOn) != "agent" || tk.KeyPolicy == nil || string(*tk.KeyPolicy) != "always" {
		t.Fatalf("traefik entry = %+v", tk)
	}
}
