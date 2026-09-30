//go:build integration

package api

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/deploy"
	"github.com/metril/certforge/internal/targets"
)

// fakeKVTarget stands in for deploy.VaultKV in server-grant tests: it
// records every write in memory instead of touching a real Vault. Parse
// delegates to the real VaultKV so a vault-kv deploy target created
// through the API still validates its config shape (mount, path, keys,
// includeKey) exactly like production; only Deploy itself is faked.
type fakeKVTarget struct {
	mu    sync.Mutex
	calls []targets.Request
	err   error
}

func (f *fakeKVTarget) Type() string                 { return "vault-kv" }
func (f *fakeKVTarget) Name() string                 { return "Vault KV" }
func (f *fakeKVTarget) Schema() json.RawMessage      { return (deploy.VaultKV{}).Schema() }
func (f *fakeKVTarget) RunsOn() targets.Mode         { return targets.Server }
func (f *fakeKVTarget) KeyPolicy() targets.KeyPolicy { return targets.Optional }

func (f *fakeKVTarget) Parse(raw json.RawMessage) (targets.Config, error) {
	return (deploy.VaultKV{}).Parse(raw)
}

func (f *fakeKVTarget) Deploy(_ context.Context, req targets.Request) (targets.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return targets.Result{}, f.err
	}
	f.calls = append(f.calls, req)
	return targets.Result{Detail: fmt.Sprintf("fake/%s (version %d)", req.CertID, len(f.calls))}, nil
}

func (f *fakeKVTarget) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// asOrg is f.as, but for a principal bound to org rather than f.org
// (TestServerGrantCrossOrg404 needs a second org f.as cannot address).
func asOrg(role string, org uuid.UUID) context.Context {
	return authn.WithPrincipal(context.Background(), authn.Principal{Kind: authn.KindUser, UserID: uuid.New(),
		Roles: []string{role}, Bindings: []authn.Binding{{Role: role, OrgID: &org}}, OrgIDs: []uuid.UUID{org}})
}

// targetCreator returns admin when config's own includeKey is true (needs
// keys:export, batch-5 review) and operator otherwise: these fixture
// helpers exist to set up a target for a later test, not to re-test
// createDeployTarget's own gate (TestServerTargetIncludeKeyRequiresKeysExport
// does that), so they always use a principal that can actually create what
// was asked for.
func (f *agentFixture) targetCreator(config map[string]interface{}) context.Context {
	if v, _ := config["includeKey"].(bool); v {
		return f.as("admin")
	}
	return f.as("operator")
}

// serverTarget swaps the fixture onto a fresh registry holding only a
// fakeKVTarget under "vault-kv" (Register panics on a duplicate type, so a
// live real-VaultKV entry can't just be re-registered in place the way the
// old deploy.Registry allowed) — set on both Deps.Targets and Dispatcher.Reg,
// the same registry instance production always keeps them sharing — then
// creates a vault-kv deploy target through the real API (so its config is
// genuinely validated: fakeKVTarget.Parse delegates to the real VaultKV),
// so Deploy calls never touch a real Vault.
func (f *agentFixture) serverTarget(t *testing.T, name string, config map[string]interface{}) (uuid.UUID, *fakeKVTarget) {
	t.Helper()
	if config == nil {
		config = map[string]interface{}{}
	}
	fake := &fakeKVTarget{}
	reg := targets.NewRegistry()
	targets.RegisterBuiltins(reg)
	reg.Register(fake)
	f.srv.d.Targets = reg
	f.srv.d.Dispatcher.Reg = reg
	res, err := f.srv.CreateDeployTarget(f.targetCreator(config), gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: name, Type: gen.DeployTargetType("vault-kv"), Config: config}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateDeployTarget201JSONResponse).Id
	return id, fake
}

// realServerTarget creates a vault-kv deploy target through the real API,
// like serverTarget, but leaves the registry's "vault-kv" entry as the
// real deploy.VaultKV{Vault: vaultProvider} — for a test that needs an
// actual Vault client (pointed at a fake Vault httptest server via
// setVaultSettings), not the in-memory fakeKVTarget.
func (f *agentFixture) realServerTarget(t *testing.T, name string, config map[string]interface{}) uuid.UUID {
	t.Helper()
	if config == nil {
		config = map[string]interface{}{}
	}
	res, err := f.srv.CreateDeployTarget(f.targetCreator(config), gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: name, Type: gen.DeployTargetType("vault-kv"), Config: config}})
	if err != nil {
		t.Fatal(err)
	}
	return res.(gen.CreateDeployTarget201JSONResponse).Id
}

// agentTarget creates a traefik (agent-run) deploy target, for the "server
// grant on an agent target is 422" case.
func (f *agentFixture) agentTarget(t *testing.T, name string) uuid.UUID {
	t.Helper()
	res, err := f.srv.CreateDeployTarget(f.as("operator"), gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: name, Type: gen.DeployTargetType("traefik"), Config: map[string]interface{}{"dir": "/etc/traefik/dynamic"}}})
	if err != nil {
		t.Fatal(err)
	}
	return res.(gen.CreateDeployTarget201JSONResponse).Id
}

// p12Layout stores a layout whose sole file is p12, never pem-only, for
// TestServerGrantValidation's "layout must be PEM-only" case.
func (f *agentFixture) p12Layout(t *testing.T, name string) uuid.UUID {
	t.Helper()
	files, _ := json.Marshal([]delivery.OutputFile{{Path: "/keystore.p12", Format: "p12", Mode: "0600"}})
	l, err := f.q.CreateLayout(context.Background(), sqlcgen.CreateLayoutParams{OrgID: f.org, Name: name, Files: files, ExtraCertIds: []uuid.UUID{}})
	if err != nil {
		t.Fatal(err)
	}
	return l.ID
}

// pemKeyLayout stores a PEM layout whose sole part is "key" (needs a key,
// but is still PEM-only), for TestServerGrantUpdateNeedsKeyGate.
func (f *agentFixture) pemKeyLayout(t *testing.T, name, path string) uuid.UUID {
	t.Helper()
	files, _ := json.Marshal([]delivery.OutputFile{{Path: path, Format: "pem", Parts: []string{"key"}, Mode: "0600"}})
	l, err := f.q.CreateLayout(context.Background(), sqlcgen.CreateLayoutParams{OrgID: f.org, Name: name, Files: files, ExtraCertIds: []uuid.UUID{}})
	if err != nil {
		t.Fatal(err)
	}
	return l.ID
}

// serverDeployment reads a server grant's own deployment row directly.
func (f *agentFixture) serverDeployment(t *testing.T, grantID uuid.UUID) (status string, versionID *uuid.UUID, lastError string) {
	t.Helper()
	err := f.pool.QueryRow(context.Background(), `SELECT status, version_id, last_error FROM server_deployments WHERE grant_id = $1`, grantID).
		Scan(&status, &versionID, &lastError)
	if err != nil {
		t.Fatal(err)
	}
	return status, versionID, lastError
}

// TestServerGrantLifecycle covers create (which deploys the certificate's
// current version to the fake KV), a new version enqueuing a fresh deploy,
// redeployGrant going pending then deployed, and delete leaving no further
// jobs enqueued.
func TestServerGrantLifecycle(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	op := f.as("operator")
	targetID, fake := f.serverTarget(t, "vault", nil)
	certID, v1 := f.currentCert(t, "web")

	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)
	if g.RunsOn != gen.RunsOnServer || g.ClientId != nil || g.ClientName != nil || g.Deployment != nil || g.ServerDeployment == nil {
		t.Fatalf("created grant shape = %+v", g)
	}
	if g.ServerDeployment.Status != gen.ServerDeploymentStatusPending {
		t.Fatalf("status = %s, want pending", g.ServerDeployment.Status)
	}
	if f.deployJobs.count(g.Id, v1) != 1 {
		t.Fatalf("deploy jobs for v1 = %d, want 1", f.deployJobs.count(g.Id, v1))
	}

	// Run the queued job: the fake KV receives the certificate's files and
	// the deployment becomes deployed.
	if err := f.srv.d.Dispatcher.Deploy(ctx, g.Id, v1); err != nil {
		t.Fatal(err)
	}
	if fake.count() != 1 {
		t.Fatalf("fake KV writes = %d, want 1", fake.count())
	}
	if status, vid, _ := f.serverDeployment(t, g.Id); status != "deployed" || vid == nil || *vid != v1 {
		t.Fatalf("deployment = %s %v, want deployed %s", status, vid, v1)
	}

	// A new certificate version: Dispatcher.OnVersion (the
	// issuance.VersionListener path) enqueues a fresh deploy and marks the
	// deployment pending again.
	v2 := f.secondVersion(t, certID, "02")
	f.srv.d.Dispatcher.OnVersion(ctx, certID, v2)
	if f.deployJobs.count(g.Id, v2) != 1 {
		t.Fatalf("deploy jobs for v2 = %d, want 1", f.deployJobs.count(g.Id, v2))
	}
	if status, vid, _ := f.serverDeployment(t, g.Id); status != "pending" || vid == nil || *vid != v2 {
		t.Fatalf("deployment after OnVersion = %s %v, want pending %s", status, vid, v2)
	}
	if err := f.srv.d.Dispatcher.Deploy(ctx, g.Id, v2); err != nil {
		t.Fatal(err)
	}
	if fake.count() != 2 {
		t.Fatalf("fake KV writes = %d, want 2", fake.count())
	}

	// redeployGrant re-enqueues the same version and marks it pending; the
	// response itself reflects the pending state (read after commit).
	rres, err := f.srv.RedeployGrant(op, gen.RedeployGrantRequestObject{OrgId: f.org, Id: g.Id})
	if err != nil {
		t.Fatal(err)
	}
	rg := rres.(gen.RedeployGrant200JSONResponse)
	if rg.ServerDeployment.Status != gen.ServerDeploymentStatusPending {
		t.Fatalf("status after redeploy = %s, want pending", rg.ServerDeployment.Status)
	}
	if f.deployJobs.count(g.Id, v2) != 2 {
		t.Fatalf("deploy jobs for v2 after redeploy = %d, want 2", f.deployJobs.count(g.Id, v2))
	}
	if err := f.srv.d.Dispatcher.Deploy(ctx, g.Id, v2); err != nil {
		t.Fatal(err)
	}
	if fake.count() != 3 {
		t.Fatalf("fake KV writes after redeploy = %d, want 3", fake.count())
	}
	// batch-5 review: grant.redeploy's own audit details carry includeKey,
	// the same as grant.create.
	if d := f.lastAuditDetails(t, "grant.redeploy", g.Id.String()); !strings.Contains(d, `"includeKey"`) {
		t.Fatalf("grant.redeploy audit details missing includeKey: %s", d)
	}

	// Delete: the grant and its server_deployments row (ON DELETE CASCADE)
	// are gone, and a later OnVersion for the same certificate enqueues
	// nothing more for it.
	if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: g.Id, Params: gen.DeleteGrantParams{}}); err != nil {
		t.Fatal(err)
	}
	if d := f.lastAuditDetails(t, "grant.delete", g.Id.String()); !strings.Contains(d, `"includeKey"`) {
		t.Fatalf("grant.delete audit details missing includeKey: %s", d)
	}
	var status string
	err = f.pool.QueryRow(ctx, `SELECT status FROM server_deployments WHERE grant_id = $1`, g.Id).Scan(&status)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("server_deployments after delete: err = %v, want ErrNoRows", err)
	}
	f.srv.d.Dispatcher.OnVersion(ctx, certID, v2)
	if f.deployJobs.count(g.Id, v2) != 2 {
		t.Fatalf("deploy jobs for v2 after delete = %d, want still 2 (no further jobs)", f.deployJobs.count(g.Id, v2))
	}
}

// TestServerDeployStaleVersionSkipped covers the batch-5 review fix: a job
// for an older version that finishes after a newer version has already
// taken over (server_deployments.version_id moved on) must do nothing at
// all — no target write, no state change — rather than overwrite the
// target with stale material and mark it deployed.
func TestServerDeployStaleVersionSkipped(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	op := f.as("operator")
	targetID, fake := f.serverTarget(t, "vault", nil)
	certID, v1 := f.currentCert(t, "web")

	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)

	// v2 arrives before the v1 job ever runs: OnVersion moves
	// server_deployments.version_id to v2 and enqueues v2's own job.
	v2 := f.secondVersion(t, certID, "02")
	f.srv.d.Dispatcher.OnVersion(ctx, certID, v2)

	// The (now stale) v1 job finally runs: Deploy must return nil, touch
	// neither the target nor server_deployments' state.
	if err := f.srv.d.Dispatcher.Deploy(ctx, g.Id, v1); err != nil {
		t.Fatalf("stale v1 job: err = %v, want nil", err)
	}
	if fake.count() != 0 {
		t.Fatalf("fake KV writes for a stale v1 job = %d, want 0", fake.count())
	}
	if status, vid, _ := f.serverDeployment(t, g.Id); status != "pending" || vid == nil || *vid != v2 {
		t.Fatalf("deployment after a stale v1 job = %s %v, want pending %s (untouched)", status, vid, v2)
	}

	// The real (v2) job still deploys normally afterward.
	if err := f.srv.d.Dispatcher.Deploy(ctx, g.Id, v2); err != nil {
		t.Fatal(err)
	}
	if fake.count() != 1 {
		t.Fatalf("fake KV writes after the real v2 job = %d, want 1", fake.count())
	}
	if status, vid, _ := f.serverDeployment(t, g.Id); status != "deployed" || vid == nil || *vid != v2 {
		t.Fatalf("deployment after v2 = %s %v, want deployed %s", status, vid, v2)
	}
}

// TestUpdateLayoutServerGrantPEMOnly covers the batch-5 review fix:
// UpdateLayout refuses to turn a layout a live server grant depends on
// into anything but PEM (the p12/jks/der 422 createServerGrant already
// enforces on the layout it was given, now enforced continuously), and an
// allowed update enqueues that grant's own redeploy.
func TestUpdateLayoutServerGrantPEMOnly(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	op := f.as("operator")
	targetID, fake := f.serverTarget(t, "vault", nil)
	certID, v1 := f.currentCert(t, "web")
	layoutID := f.layout(t, "l1", "/etc/ssl/web.pem")

	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID, LayoutId: &layoutID}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)
	if err := f.srv.d.Dispatcher.Deploy(ctx, g.Id, v1); err != nil {
		t.Fatal(err)
	}
	if fake.count() != 1 {
		t.Fatalf("fake KV writes at create = %d, want 1", fake.count())
	}

	// A non-PEM file is 422, exactly like createServerGrant's own rule — a
	// valid p12 password is included so the only thing that can possibly
	// refuse this update is the PEM-only rule itself, not an unrelated
	// missing-password 422 that would happen to carry the same status.
	pw := "a-valid-p12-password"
	p12Body := &gen.LayoutInput{Name: "l1", Password: &pw,
		Files: []gen.OutputFile{{Path: "/keystore.p12", Format: gen.OutputFormat("p12"), Mode: "0600"}}}
	_, err = f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: layoutID, Body: p12Body})
	wantStatus(t, err, 422)
	if status, _, _ := f.serverDeployment(t, g.Id); status != "deployed" {
		t.Fatalf("a rejected update must not touch the deployment: status = %s, want deployed", status)
	}

	// A PEM-only update is allowed and enqueues the server grant's redeploy.
	if _, err := f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: layoutID, Body: layoutInput("l1", "/etc/ssl/web2.pem")}); err != nil {
		t.Fatal(err)
	}
	if status, vid, _ := f.serverDeployment(t, g.Id); status != "pending" || vid == nil || *vid != v1 {
		t.Fatalf("deployment after a pem-only layout update = %s %v, want pending %s", status, vid, v1)
	}
	if err := f.srv.d.Dispatcher.Deploy(ctx, g.Id, v1); err != nil {
		t.Fatal(err)
	}
	if fake.count() != 2 {
		t.Fatalf("fake KV writes after the layout update's redeploy = %d, want 2", fake.count())
	}
}

// TestServerGrantUpdateNeedsKeyGate covers the batch-5 review fix:
// updateServerGrant runs the same needsKey→keys:export and has-key 422
// checks createServerGrant does, not just the PEM-only format check — a
// layout edit that newly needs a key is gated exactly like a create would
// be, both for the caller's own permission and for the certificate having
// a stored key at all. Both grants here live on an includeKey:true target
// (final review finding 4 changed what a key-needing layout on an
// includeKey:false target means — always 422, not a permission gate; see
// TestServerGrantKeyLayoutRequiresIncludeKey), so keyLayoutID's own gate
// is purely the keys:export/has-key one this test targets.
func TestServerGrantUpdateNeedsKeyGate(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	admin := f.as("admin")

	plainLayoutID := f.layout(t, "plain", "/etc/ssl/plain.pem")
	keyLayoutID := f.pemKeyLayout(t, "keyed", "/etc/ssl/plain.key")

	// includeKey:true (created by admin, targetCreator's own rule): any
	// grant onto it needs keys:export regardless of its layout.
	targetID, _ := f.serverTarget(t, "vault", map[string]interface{}{"includeKey": true})
	certID, _ := f.currentCert(t, "web")
	res, err := f.srv.CreateServerGrant(admin, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID, LayoutId: &plainLayoutID}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)

	// Editing its layout to one that also needs a key is 403 for operator,
	// 200 for admin (who holds keys:export) — the target already needs one
	// regardless, so this isolates the keys:export gate from finding 4's
	// new includeKey-mismatch 422.
	_, err = f.srv.UpdateGrant(op, gen.UpdateGrantRequestObject{OrgId: f.org, Id: g.Id,
		Body: &gen.GrantUpdate{Delivery: gen.GrantDelivery("push"), LayoutId: &keyLayoutID}})
	wantStatus(t, err, 403)
	if _, err := f.srv.UpdateGrant(admin, gen.UpdateGrantRequestObject{OrgId: f.org, Id: g.Id,
		Body: &gen.GrantUpdate{Delivery: gen.GrantDelivery("push"), LayoutId: &keyLayoutID}}); err != nil {
		t.Fatalf("admin update to a key-needing layout: %v", err)
	}
	if d := f.lastAuditDetails(t, "grant.update", g.Id.String()); !strings.Contains(d, `"includeKey"`) {
		t.Fatalf("grant.update audit details missing includeKey: %s", d)
	}

	// A keyless certificate on an includeKey:true target: even an admin
	// (keys:export held) gets the has-key 422 — at create time, since
	// finding 4 means the has-key check now only ever runs alongside
	// includeKey:true, which gates unconditionally regardless of layout
	// (the plain layout here needs no key of its own).
	leafDER, _, _ := realCert(t, "server-grant-keyless.example.test", 9601)
	body := pemCert(leafDER)
	ures, err := f.srv.UploadCertificate(op, gen.UploadCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateUpload{Name: "server-grant-keyless", CertificatePem: &body}})
	if err != nil {
		t.Fatal(err)
	}
	keylessCertID := ures.(gen.UploadCertificate201JSONResponse).Id
	targetID2, _ := f.serverTarget(t, "vault2", map[string]interface{}{"includeKey": true})
	_, err = f.srv.CreateServerGrant(admin, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID2,
		Body: &gen.ServerGrantInput{CertificateId: keylessCertID, LayoutId: &plainLayoutID}})
	wantStatus(t, err, 422)
}

// TestServerGrantKeyLayoutRequiresIncludeKey covers the final review
// finding 4 controller ruling: a layout that renders a private key on a
// target without includeKey is refused (422) at both create and update,
// regardless of the caller's own permissions (even an admin holding
// keys:export) — Dispatcher.Deploy only ever fetches a key when the
// target's own includeKey is set, so this combination could never actually
// be deployed; it must never be storable in the first place.
func TestServerGrantKeyLayoutRequiresIncludeKey(t *testing.T) {
	f := newAgentFixture(t)
	admin := f.as("admin")

	plainLayoutID := f.layout(t, "plain2", "/etc/ssl/plain2.pem")
	keyLayoutID := f.pemKeyLayout(t, "keyed2", "/etc/ssl/plain2.key")
	targetID, _ := f.serverTarget(t, "vault-nokey", nil)
	certID, _ := f.currentCert(t, "web2")

	_, err := f.srv.CreateServerGrant(admin, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID, LayoutId: &keyLayoutID}})
	wantStatus(t, err, 422)

	res, err := f.srv.CreateServerGrant(admin, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID, LayoutId: &plainLayoutID}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)
	_, err = f.srv.UpdateGrant(admin, gen.UpdateGrantRequestObject{OrgId: f.org, Id: g.Id,
		Body: &gen.GrantUpdate{Delivery: gen.GrantDelivery("push"), LayoutId: &keyLayoutID}})
	wantStatus(t, err, 422)
}

// TestServerGrantValidation covers createServerGrant's own checks: an
// agent-run target is 422, a non-PEM layout is 422, includeKey without
// keys:export is 403, and a duplicate (target, certificate) pair is 409.
func TestServerGrantValidation(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	admin := f.as("admin")

	agentTargetID := f.agentTarget(t, "traefik")
	certID1, _ := f.currentCert(t, "web1")
	_, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: agentTargetID,
		Body: &gen.ServerGrantInput{CertificateId: certID1}})
	wantStatus(t, err, 422)

	targetID2, _ := f.serverTarget(t, "vault2", nil)
	certID2, _ := f.currentCert(t, "web2")
	layoutID := f.p12Layout(t, "p12-layout")
	_, err = f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID2,
		Body: &gen.ServerGrantInput{CertificateId: certID2, LayoutId: &layoutID}})
	wantStatus(t, err, 422)

	targetID3, _ := f.serverTarget(t, "vault-key", map[string]interface{}{"includeKey": true})
	certID3, _ := f.currentCert(t, "web3")
	_, err = f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID3,
		Body: &gen.ServerGrantInput{CertificateId: certID3}})
	wantStatus(t, err, 403)
	// The same call succeeds for an admin (who holds keys:export, a
	// global-only action).
	if _, err := f.srv.CreateServerGrant(admin, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID3,
		Body: &gen.ServerGrantInput{CertificateId: certID3}}); err != nil {
		t.Fatalf("admin create with includeKey: %v", err)
	}

	targetID4, _ := f.serverTarget(t, "vault4", nil)
	certID4, _ := f.currentCert(t, "web4")
	if _, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID4,
		Body: &gen.ServerGrantInput{CertificateId: certID4}}); err != nil {
		t.Fatal(err)
	}
	_, err = f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID4,
		Body: &gen.ServerGrantInput{CertificateId: certID4}})
	wantStatus(t, err, 409)
}

// TestServerGrantCrossOrg404 covers the pre-flight ruling: update, delete
// and redeploy on a server grant from a different org are all 404 (the
// grant is org-scoped through deploy_targets.org_id, never findable from
// another org).
func TestServerGrantCrossOrg404(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	targetID, _ := f.serverTarget(t, "vault", nil)
	certID, _ := f.currentCert(t, "web")
	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)

	org2 := dbtest.Org(t, f.pool)
	ctx2 := asOrg("operator", org2)

	_, err = f.srv.UpdateGrant(ctx2, gen.UpdateGrantRequestObject{OrgId: org2, Id: g.Id,
		Body: &gen.GrantUpdate{Delivery: gen.GrantDelivery("push")}})
	wantStatus(t, err, 404)

	_, err = f.srv.RedeployGrant(ctx2, gen.RedeployGrantRequestObject{OrgId: org2, Id: g.Id})
	wantStatus(t, err, 404)

	_, err = f.srv.DeleteGrant(ctx2, gen.DeleteGrantRequestObject{OrgId: org2, Id: g.Id, Params: gen.DeleteGrantParams{}})
	wantStatus(t, err, 404)
}

// TestServerGrantInvisibleToAgents covers the pre-flight ruling that a
// server grant never enters agents.Service's own machinery: OnVersion and
// SweepDeployments run clean (no error, no deployments row ever created
// for it — the deployments table is agent grants only), and it never shows
// up in ListCertificateDeployments, the client-grant deployment listing.
func TestServerGrantInvisibleToAgents(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	op := f.as("operator")
	targetID, _ := f.serverTarget(t, "vault", nil)
	certID, v1 := f.currentCert(t, "web")
	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)

	if err := f.svc.SweepDeployments(ctx); err != nil {
		t.Fatalf("SweepDeployments: %v", err)
	}
	f.svc.OnVersion(ctx, certID, v1) // logs only on error; nothing to assert but that it doesn't touch this grant

	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM deployments WHERE grant_id = $1`, g.Id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("deployments rows for a server grant = %d, want 0", n)
	}

	lres, err := f.srv.ListCertificateDeployments(op, gen.ListCertificateDeploymentsRequestObject{OrgId: f.org, Id: certID})
	if err != nil {
		t.Fatal(err)
	}
	if items := lres.(gen.ListCertificateDeployments200JSONResponse).Items; len(items) != 0 {
		t.Fatalf("ListCertificateDeployments = %+v, want empty (server grants are not client deployments)", items)
	}
}

// fakeVaultKVDenied is a minimal Vault KV v2 stand-in whose write always
// fails with an error that echoes token (mirroring how a real Vault error
// can quote the caller's own token back, for example a permission-denied
// message) and a long filler, for TestServerDeployFailureRecorded's
// redaction and truncation coverage. /v1/auth/token/lookup-self is handled
// the same way fakeVaultPKI's is, for the client's background renewal loop.
func fakeVaultKVDenied(t *testing.T, token, filler string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": 3600, "policies": []string{"default"}, "renewable": false}})
	})
	mux.HandleFunc("/v1/secret/data/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		msg := fmt.Sprintf("permission denied for token %q: %s", r.Header.Get("X-Vault-Token"), filler)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestServerDeployFailureRecorded covers Dispatcher.Deploy's failure path
// end to end, through the real deploy.VaultKV and internal/vault.Client
// (not a fake Target): the deployment status becomes failed, last_error is
// truncated to <= 1000 bytes on a valid UTF-8 boundary, and — the batch-5
// review's own ask — the caller's Vault token never appears in it, even
// though the fake Vault's own error text echoes it back verbatim. Token
// redaction itself happens inside internal/vault.Client.Redact (also
// covered directly by TestClientRedactsToken); this test is the one that
// proves the whole server-deploy path never loses that property between
// the client and server_deployments.last_error.
func TestServerDeployFailureRecorded(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	op := f.as("operator")

	token := "s.thisIsASecretVaultToken1234567890"
	// 3-byte runes so a naive byte-1000 cut lands mid-character.
	filler := strings.Repeat("世", 400)
	fv := fakeVaultKVDenied(t, token, filler)
	f.setVaultSettings(t, `{"address":"`+fv.URL+`","authMethod":"token","token":"`+token+`"}`)

	targetID := f.realServerTarget(t, "vault", nil)
	certID, v1 := f.currentCert(t, "web")
	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)

	if err := f.srv.d.Dispatcher.Deploy(ctx, g.Id, v1); err == nil {
		t.Fatal("Deploy returned no error")
	}

	status, vid, lastError := f.serverDeployment(t, g.Id)
	if status != "failed" {
		t.Fatalf("status = %s, want failed", status)
	}
	if vid == nil || *vid != v1 {
		t.Fatalf("version_id = %v, want %s", vid, v1)
	}
	if len(lastError) > 1000 {
		t.Fatalf("last_error length = %d, want <= 1000", len(lastError))
	}
	if !utf8.ValidString(lastError) {
		t.Fatalf("last_error is not valid UTF-8 (truncated mid-rune): %q", lastError)
	}
	if strings.Contains(lastError, token) {
		t.Fatalf("last_error leaks the Vault token: %q", lastError)
	}
	if !strings.Contains(lastError, "permission denied") {
		t.Fatalf("last_error lost the underlying error text: %q", lastError)
	}
}

// TestServerGrantExtraCertRedeployed covers final review finding 5 (first
// half): OnVersion also enqueues live server grants whose layout's
// extra_cert_ids contains the certificate that just got a new version —
// the grant's own certificate did not change, so it redeploys onto its
// own current version, not the extra certificate's new one.
func TestServerGrantExtraCertRedeployed(t *testing.T) {
	f := newAgentFixture(t)
	ctx := context.Background()
	op := f.as("operator")

	extraCertID, _ := f.currentCert(t, "extra")
	certID, v1 := f.currentCert(t, "main")

	files, err := json.Marshal([]delivery.OutputFile{{Path: "/etc/ssl/main.pem", Format: "pem", Parts: []string{"fullchain"}, Mode: "0644"}})
	if err != nil {
		t.Fatal(err)
	}
	layout, err := f.q.CreateLayout(ctx, sqlcgen.CreateLayoutParams{OrgID: f.org, Name: "extra-layout", Files: files, ExtraCertIds: []uuid.UUID{extraCertID}})
	if err != nil {
		t.Fatal(err)
	}

	targetID, _ := f.serverTarget(t, "vault-extra", nil)
	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID, LayoutId: &layout.ID}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)
	if f.deployJobs.count(g.Id, v1) != 1 {
		t.Fatalf("deploy jobs at create = %d, want 1", f.deployJobs.count(g.Id, v1))
	}

	extraV2 := f.secondVersion(t, extraCertID, "e2")
	f.srv.d.Dispatcher.OnVersion(ctx, extraCertID, extraV2)

	// The grant's own certificate's current version (v1, unchanged) is
	// what gets redeployed, not the extra certificate's new version.
	if f.deployJobs.count(g.Id, v1) != 2 {
		t.Fatalf("deploy jobs for the grant's own version after the extra cert's new version = %d, want 2", f.deployJobs.count(g.Id, v1))
	}
	if status, vid, _ := f.serverDeployment(t, g.Id); status != "pending" || vid == nil || *vid != v1 {
		t.Fatalf("deployment after extra-cert OnVersion = %s %v, want pending %s", status, vid, v1)
	}
}

// TestServerGrantRedeploysOnCertificateRename covers final review finding
// 5 (second half): a certificate rename re-enqueues its own live server
// grants (Dispatcher.ResyncCertificateRename, composed into serve.go's
// RenameHook alongside agents.Service.ResyncCertificateRename) — a
// vault-kv target's default path embeds the certificate's own name
// ({name}), so the grant must redeploy to write its material at the new
// path even though the version itself did not change.
func TestServerGrantRedeploysOnCertificateRename(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")

	targetID, _ := f.serverTarget(t, "vault-rename", nil)
	certID, v1 := f.currentCert(t, "rename-me")
	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)
	if f.deployJobs.count(g.Id, v1) != 1 {
		t.Fatalf("deploy jobs at create = %d, want 1", f.deployJobs.count(g.Id, v1))
	}

	if _, err := f.srv.UpdateCertificate(op, gen.UpdateCertificateRequestObject{OrgId: f.org, Id: certID,
		Body: &gen.CertificateInput{Name: "renamed-now", CommonName: "rename-me.example.test"}}); err != nil {
		t.Fatal(err)
	}

	if f.deployJobs.count(g.Id, v1) != 2 {
		t.Fatalf("deploy jobs after rename = %d, want 2", f.deployJobs.count(g.Id, v1))
	}
	if status, vid, _ := f.serverDeployment(t, g.Id); status != "pending" || vid == nil || *vid != v1 {
		t.Fatalf("deployment after rename = %s %v, want pending %s", status, vid, v1)
	}
}

// TestServerGrantUploadVersionKeylessGate422 covers final review finding 3
// (first half): LiveGrantsNeedKeyTx (UploadVersion's own keyless-upload
// gate, R10) now sees live server grants too, not only agent grants — a
// server grant on an includeKey:true target needs a key exactly like a
// Traefik agent target already does, so uploading a keyless version onto
// a certificate a live server grant depends on is refused (409, the same
// ConflictError this hook has always returned for an agent grant), not
// silently accepted and left for the next deploy to fail with no key to
// render.
func TestServerGrantUploadVersionKeylessGate422(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	admin := f.as("admin")

	targetID, _ := f.serverTarget(t, "vault-upload-gate", map[string]interface{}{"includeKey": true})

	// An uploaded (unmanaged) certificate with a key, so UploadCertificateVersion applies to it.
	leaf1DER, _, key1PKCS8 := realCert(t, "server-grant-upload-gate.example.test", 9701)
	body1 := pemCert(leaf1DER)
	keyBody1 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key1PKCS8}))
	ures, err := f.srv.UploadCertificate(op, gen.UploadCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateUpload{Name: "server-grant-upload-gate", CertificatePem: &body1, PrivateKeyPem: &keyBody1}})
	if err != nil {
		t.Fatal(err)
	}
	certID := ures.(gen.UploadCertificate201JSONResponse).Id

	_, err = f.srv.CreateServerGrant(admin, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID}})
	if err != nil {
		t.Fatal(err)
	}

	leaf2DER, _, _ := realCert(t, "server-grant-upload-gate.example.test", 9702)
	body2 := pemCert(leaf2DER)
	_, err = f.srv.UploadCertificateVersion(op, gen.UploadCertificateVersionRequestObject{OrgId: f.org, Id: certID,
		Body: &gen.CertificateVersionUpload{CertificatePem: &body2}})
	wantStatus(t, err, 409)
}

// TestUpdateDeployTargetIncludeKeyNeedsLiveGrantKeys covers final review
// finding 3 (second half): UpdateDeployTarget turning includeKey on is
// refused (422) when a live server grant on this target has a certificate
// with no stored key — the same has-key rule createServerGrant already
// runs, now also enforced at the target level so a target can never end
// up needing a key none of its grants can supply.
func TestUpdateDeployTargetIncludeKeyNeedsLiveGrantKeys(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	admin := f.as("admin")

	targetID, _ := f.serverTarget(t, "vault-target-gate", nil)
	leafDER, _, _ := realCert(t, "server-target-gate-keyless.example.test", 9702)
	body := pemCert(leafDER)
	ures, err := f.srv.UploadCertificate(op, gen.UploadCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateUpload{Name: "server-target-gate-keyless", CertificatePem: &body}})
	if err != nil {
		t.Fatal(err)
	}
	keylessCertID := ures.(gen.UploadCertificate201JSONResponse).Id
	if _, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: keylessCertID}}); err != nil {
		t.Fatal(err)
	}

	_, err = f.srv.UpdateDeployTarget(admin, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.DeployTargetInput{Name: "vault-target-gate", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"includeKey": true}}})
	wantStatus(t, err, 422)
}

// TestServerGrantDependentsListed covers final review finding 2:
// LayoutDependents/DeployTargetDependents used to INNER JOIN clients,
// which excludes a server grant (client_id IS NULL) entirely — deleting a
// layout or target used only by a server grant silently succeeded (the
// 409's own len(deps)>0 check saw nothing) instead of naming the
// still-live grant. Both now LEFT JOIN clients and name the deploy target
// in place of a client for a server grant's row.
func TestServerGrantDependentsListed(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	targetID, _ := f.serverTarget(t, "vault-dep", nil)
	certID, _ := f.currentCert(t, "web-dep")
	layoutID := f.layout(t, "dep-layout", "/etc/ssl/dep.pem")

	if _, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID, LayoutId: &layoutID}}); err != nil {
		t.Fatal(err)
	}

	_, err := f.srv.DeleteLayout(op, gen.DeleteLayoutRequestObject{OrgId: f.org, Id: layoutID})
	wantStatus(t, err, 409)
	var he *HTTPError
	if !errors.As(err, &he) || !strings.Contains(he.Detail, "vault-dep/web-dep") {
		t.Fatalf("DeleteLayout 409 = %v, want it to name the target/certificate (vault-dep/web-dep)", err)
	}

	_, err = f.srv.DeleteDeployTarget(op, gen.DeleteDeployTargetRequestObject{OrgId: f.org, Id: targetID})
	wantStatus(t, err, 409)
	if !errors.As(err, &he) || !strings.Contains(he.Detail, "vault-dep/web-dep") {
		t.Fatalf("DeleteDeployTarget 409 = %v, want it to name the target/certificate (vault-dep/web-dep)", err)
	}
}
