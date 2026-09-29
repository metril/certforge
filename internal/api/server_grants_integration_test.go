//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/deploy"
)

// fakeKVTarget stands in for deploy.VaultKV in server-grant tests: it
// records every write in memory instead of touching a real Vault.
// ParseConfig delegates to the real VaultKV so a vault-kv deploy target
// created through the API still validates its config shape (mount, path,
// keys, includeKey) exactly like production; only Deploy itself is faked.
type fakeKVTarget struct {
	mu    sync.Mutex
	calls []deploy.Request
	err   error
}

func (f *fakeKVTarget) Type() string            { return "vault-kv" }
func (f *fakeKVTarget) Schema() json.RawMessage { return json.RawMessage(`{}`) }

func (f *fakeKVTarget) ParseConfig(raw json.RawMessage) (json.RawMessage, error) {
	return deploy.VaultKV{}.ParseConfig(raw)
}

func (f *fakeKVTarget) Deploy(_ context.Context, req deploy.Request) (deploy.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return deploy.Result{}, f.err
	}
	f.calls = append(f.calls, req)
	return deploy.Result{Path: "fake/" + req.CertID, Version: len(f.calls)}, nil
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

// serverTarget creates a vault-kv deploy target through the real API (so
// its config is genuinely validated) and swaps its registry entry for a
// fresh fakeKVTarget, so Deploy calls never touch a real Vault.
func (f *agentFixture) serverTarget(t *testing.T, name string, config map[string]interface{}) (uuid.UUID, *fakeKVTarget) {
	t.Helper()
	if config == nil {
		config = map[string]interface{}{}
	}
	res, err := f.srv.CreateDeployTarget(f.as("operator"), gen.CreateDeployTargetRequestObject{OrgId: f.org,
		Body: &gen.DeployTargetInput{Name: name, Type: gen.DeployTargetType("vault-kv"), Config: config}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateDeployTarget201JSONResponse).Id
	fake := &fakeKVTarget{}
	f.srv.d.Deploy.Register("Fake Vault KV", fake)
	return id, fake
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

	// Delete: the grant and its server_deployments row (ON DELETE CASCADE)
	// are gone, and a later OnVersion for the same certificate enqueues
	// nothing more for it.
	if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: g.Id, Params: gen.DeleteGrantParams{}}); err != nil {
		t.Fatal(err)
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

// TestServerDeployFailureRecorded covers Dispatcher.Deploy's failure path:
// the target's error is recorded as last_error, truncated to <= 1000
// chars, and the deployment status becomes failed. (Vault-token redaction
// itself is internal/vault.Client.Redact's own responsibility, already
// covered by TestClientRedactsToken; every Target implementation that
// talks to Vault, such as vault-kv, returns errors already redacted.)
func TestServerDeployFailureRecorded(t *testing.T) {
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

	longMsg := "vault: write failed: " + strings.Repeat("boom ", 300)
	fake.err = errors.New(longMsg)
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
	if !strings.HasPrefix(longMsg, lastError) {
		t.Fatalf("last_error %q is not a prefix of the original message", lastError)
	}
}
