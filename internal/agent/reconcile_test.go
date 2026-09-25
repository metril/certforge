//go:build unix

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
)

type fakeAPI struct {
	as      agentproto.Assignments
	bundles map[uuid.UUID]agentproto.Bundle
	fetched int
}

func (f *fakeAPI) Assignments(context.Context) (agentproto.Assignments, error) { return f.as, nil }
func (f *fakeAPI) Bundle(_ context.Context, id uuid.UUID) (agentproto.Bundle, error) {
	f.fetched++
	return f.bundles[id], nil
}

func newTestIdentity(t *testing.T) *Identity {
	return &Identity{Dir: t.TempDir(), State: State{Grants: map[uuid.UUID]GrantState{}}}
}

func layoutGrant(dir, name string) (agentproto.Assignment, agentproto.Bundle) {
	p := filepath.Join(dir, "out", name+".pem")
	data := []byte("PEM-" + name)
	a := agentproto.Assignment{ID: uuid.New(), CertificateName: name, VersionID: uuid.New(),
		Files: []agentproto.FileSpec{{Path: p, Mode: "0644", SHA256: delivery.Digest(data)}}, Hooks: []agentproto.HookSpec{}}
	return a, agentproto.Bundle{VersionID: a.VersionID, Files: []agentproto.BundleFile{{Path: p, Mode: "0644", Content: data}}}
}

func TestReconcileDeploysThenReportsUnchanged(t *testing.T) {
	dir := t.TempDir()
	a, b := layoutGrant(dir, "web")
	api := &fakeAPI{as: agentproto.Assignments{Revision: 4, Grants: []agentproto.Assignment{a}}, bundles: map[uuid.UUID]agentproto.Bundle{a.ID: b}}
	id := newTestIdentity(t)
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}), ID: id, Log: discard}
	for i := range 2 {
		rep, err := r.Reconcile(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if rep.Revision != 4 || len(rep.Results) != 1 || rep.Results[0].State != agentproto.StateOK ||
			rep.Results[0].Installed[0].SHA256 != a.Files[0].SHA256 || rep.Results[0].VersionID != a.VersionID {
			t.Fatalf("run %d report %+v", i, rep)
		}
	}
	if api.fetched != 1 || id.State.Revision != 4 || len(id.State.Grants) != 1 {
		t.Fatalf("fetched %d state %+v", api.fetched, id.State)
	}
	if _, err := os.Stat(filepath.Join(id.Dir, "state.json")); err != nil {
		t.Fatal("state not saved")
	}
}

func TestReconcileRedeploysTamperedFile(t *testing.T) {
	dir := t.TempDir()
	a, b := layoutGrant(dir, "web")
	api := &fakeAPI{as: agentproto.Assignments{Revision: 1, Grants: []agentproto.Assignment{a}}, bundles: map[uuid.UUID]agentproto.Bundle{a.ID: b}}
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}), ID: newTestIdentity(t), Log: discard}
	_, _ = r.Reconcile(context.Background())
	_ = os.WriteFile(a.Files[0].Path, []byte("tampered"), 0o644)
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(a.Files[0].Path)
	if api.fetched != 2 || string(got) != "PEM-web" {
		t.Fatalf("fetched %d content %q", api.fetched, got)
	}
}

func TestReconcileRemovesRemovedAndOrphans(t *testing.T) {
	dir := t.TempDir()
	a1, b1 := layoutGrant(dir, "one")
	a2, b2 := layoutGrant(dir, "two")
	api := &fakeAPI{as: agentproto.Assignments{Revision: 1, Grants: []agentproto.Assignment{a1, a2}},
		bundles: map[uuid.UUID]agentproto.Bundle{a1.ID: b1, a2.ID: b2}}
	id := newTestIdentity(t)
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}), ID: id, Log: discard}
	_, _ = r.Reconcile(context.Background())
	api.as = agentproto.Assignments{Revision: 2, Grants: []agentproto.Assignment{},
		Removed: []agentproto.Removal{{ID: a1.ID, Files: []string{a1.Files[0].Path}}}}
	rep, err := r.Reconcile(context.Background())
	if err != nil || len(rep.Results) != 1 || rep.Results[0].GrantID != a1.ID || rep.Results[0].State != agentproto.StateOK {
		t.Fatalf("report %+v %v", rep, err)
	}
	for _, p := range []string{a1.Files[0].Path, a2.Files[0].Path} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s still present", p)
		}
	}
	if len(id.State.Grants) != 0 {
		t.Fatalf("state %+v", id.State.Grants)
	}
}

func TestReconcileKeepsPathsClaimedByLiveGrant(t *testing.T) {
	dir := t.TempDir()
	a1, b1 := layoutGrant(dir, "web")
	api := &fakeAPI{as: agentproto.Assignments{Revision: 1, Grants: []agentproto.Assignment{a1}}, bundles: map[uuid.UUID]agentproto.Bundle{a1.ID: b1}}
	id := newTestIdentity(t)
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}), ID: id, Log: discard}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The grant was deleted and the certificate granted again with the same
	// layout before the agent confirmed: same path, new grant.
	a2, b2 := layoutGrant(dir, "web")
	api.as = agentproto.Assignments{Revision: 2, Grants: []agentproto.Assignment{a2},
		Removed: []agentproto.Removal{{ID: a1.ID, Files: []string{a1.Files[0].Path}}}}
	api.bundles[a2.ID] = b2
	rep, err := r.Reconcile(context.Background())
	if err != nil || len(rep.Results) != 2 {
		t.Fatalf("report %+v %v", rep, err)
	}
	for _, res := range rep.Results {
		if res.State != agentproto.StateOK {
			t.Fatalf("result %+v", res)
		}
	}
	if got, err := os.ReadFile(a2.Files[0].Path); err != nil || string(got) != "PEM-web" {
		t.Fatalf("live grant's file removed: %q %v", got, err)
	}
	if _, ok := id.State.Grants[a1.ID]; ok || len(id.State.Grants) != 1 {
		t.Fatalf("state %+v", id.State.Grants)
	}
}

func TestStateInstalled(t *testing.T) {
	dir := t.TempDir()
	a, b := layoutGrant(dir, "web")
	id := newTestIdentity(t)
	r := &Reconciler{API: &fakeAPI{as: agentproto.Assignments{Grants: []agentproto.Assignment{a}}, bundles: map[uuid.UUID]agentproto.Bundle{a.ID: b}},
		Deployer: testDeployer([]string{dir}), ID: id, Log: discard}
	_, _ = r.Reconcile(context.Background())
	inst := id.State.Installed()
	if len(inst) != 1 || inst[0].GrantID != a.ID || inst[0].SHA256 != a.Files[0].SHA256 || inst[0].MTime.IsZero() {
		t.Fatalf("installed %+v", inst)
	}
	_ = os.Remove(a.Files[0].Path)
	if inst = id.State.Installed(); inst[0].SHA256 != "" {
		t.Fatalf("missing file digest %q", inst[0].SHA256)
	}
}
