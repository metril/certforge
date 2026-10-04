//go:build integration

package api

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
)

func (f *agentFixture) kvGrant(t *testing.T, targetID, certID uuid.UUID) (gen.CreateServerGrant201JSONResponse, error) {
	t.Helper()
	res, err := f.srv.CreateServerGrant(f.as("operator"), gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID}})
	if err != nil {
		return gen.CreateServerGrant201JSONResponse{}, err
	}
	return res.(gen.CreateServerGrant201JSONResponse), nil
}

// TestServerGrantPathCollisionOnCreate covers S4(a): two certificates whose
// names share a SafeName, or any two on a template without {name}/{cert},
// cannot both be granted to one vault-kv target.
func TestServerGrantPathCollisionOnCreate(t *testing.T) {
	f := newAgentFixture(t)
	targetID, _ := f.serverTarget(t, "kv-safename", nil)
	a, _ := f.currentCert(t, "Web.One")
	b, _ := f.currentCert(t, "web.one")
	if _, err := f.kvGrant(t, targetID, a); err != nil {
		t.Fatal(err)
	}
	_, err := f.kvGrant(t, targetID, b)
	wantStatus(t, err, 409)

	fixed, _ := f.serverTarget(t, "kv-fixed", map[string]interface{}{"path": "certforge/{org}/shared"})
	c, _ := f.currentCert(t, "c1")
	d, _ := f.currentCert(t, "c2")
	if _, err := f.kvGrant(t, fixed, c); err != nil {
		t.Fatal(err)
	}
	_, err = f.kvGrant(t, fixed, d)
	wantStatus(t, err, 409)
}

// TestServerGrantPathCollisionOnUpdate covers S4(a) on grant update and on a
// target edit that would make two live grants collide.
func TestServerGrantPathCollisionOnUpdate(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	targetID, _ := f.serverTarget(t, "kv-update", nil)
	a, _ := f.currentCert(t, "alpha")
	b, _ := f.currentCert(t, "beta")
	ga, err := f.kvGrant(t, targetID, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.kvGrant(t, targetID, b); err != nil {
		t.Fatal(err)
	}

	// A target edit to a constant path would collide.
	_, err = f.srv.UpdateDeployTarget(op, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.DeployTargetInput{Name: "kv-update", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"path": "certforge/{org}/same"}}})
	wantStatus(t, err, 409)

	// A pre-existing collision (written behind the API's back) blocks a grant update.
	if _, err := f.pool.Exec(context.Background(), `UPDATE deploy_targets SET config = '{"path":"certforge/x/same"}' WHERE id = $1`, targetID); err != nil {
		t.Fatal(err)
	}
	_, err = f.srv.UpdateGrant(op, gen.UpdateGrantRequestObject{OrgId: f.org, Id: ga.Id, Body: &gen.GrantUpdate{}})
	wantStatus(t, err, 409)
}

// TestServerGrantPathCollisionOnRename covers S4(a) on a certificate rename.
func TestServerGrantPathCollisionOnRename(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	targetID, _ := f.serverTarget(t, "kv-rename", nil)
	a, _ := f.currentCert(t, "alpha")
	b, _ := f.currentCert(t, "beta")
	for _, id := range []uuid.UUID{a, b} {
		if _, err := f.kvGrant(t, targetID, id); err != nil {
			t.Fatal(err)
		}
	}
	_, err := f.srv.UpdateCertificate(op, gen.UpdateCertificateRequestObject{OrgId: f.org, Id: b,
		Body: &gen.CertificateInput{Name: "ALPHA", CommonName: "beta.example.test"}})
	wantStatus(t, err, 409)
	if _, err := f.srv.UpdateCertificate(op, gen.UpdateCertificateRequestObject{OrgId: f.org, Id: b,
		Body: &gen.CertificateInput{Name: "gamma", CommonName: "beta.example.test"}}); err != nil {
		t.Fatalf("a non-colliding rename: %v", err)
	}
}

// TestVaultKVTargetOrgPrefix covers S4(b): a principal without global
// delivery write keeps vault-kv paths under certforge/<org slug>/; a global
// admin may use any path; an unchanged stored path is grandfathered.
func TestVaultKVTargetOrgPrefix(t *testing.T) {
	f := newAgentFixture(t)
	var slug string
	if err := f.pool.QueryRow(context.Background(), `SELECT slug FROM orgs WHERE id = $1`, f.org).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	create := func(ctx context.Context, name, path string) error {
		_, err := f.srv.CreateDeployTarget(ctx, gen.CreateDeployTargetRequestObject{OrgId: f.org,
			Body: &gen.DeployTargetInput{Name: name, Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"path": path}}})
		return err
	}
	op := f.as("operator")
	wantStatus(t, create(op, "t1", "other/{name}"), 403)
	wantStatus(t, create(op, "t2", "certforge/some-other-org/{name}"), 403)
	wantStatus(t, create(op, "t3", "{name}"), 403)
	if err := create(op, "t4", "certforge/{org}/deep/{name}"); err != nil {
		t.Fatal(err)
	}
	if err := create(op, "t5", "certforge/"+slug+"/literal/{name}"); err != nil {
		t.Fatal(err)
	}
	admin := f.as("admin")
	if err := create(admin, "t6", "anywhere/{name}"); err != nil {
		t.Fatal(err)
	}

	// Grandfathering: the operator may save the admin's target unchanged, not repoint it.
	targets, err := f.srv.ListDeployTargets(op, gen.ListDeployTargetsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	for _, tg := range targets.(gen.ListDeployTargets200JSONResponse).Items {
		if tg.Name == "t6" {
			id = tg.Id
		}
	}
	update := func(path string) error {
		_, err := f.srv.UpdateDeployTarget(op, gen.UpdateDeployTargetRequestObject{OrgId: f.org, Id: id,
			Body: &gen.DeployTargetInput{Name: "t6-renamed", Type: gen.DeployTargetType("vault-kv"), Config: map[string]interface{}{"path": path}}})
		return err
	}
	if err := update("anywhere/{name}"); err != nil {
		t.Fatalf("unchanged stored path: %v", err)
	}
	wantStatus(t, update("elsewhere/{name}"), 403)
}
