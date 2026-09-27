//go:build unix

package agent

import (
	"context"
	"encoding/json"
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

// verp returns a pointer to v, for Assignment.VersionID literals.
func verp(v uuid.UUID) *uuid.UUID { return &v }

func layoutGrant(dir, name string) (agentproto.Assignment, agentproto.Bundle) {
	p := filepath.Join(dir, "out", name+".pem")
	data := []byte("PEM-" + name)
	versionID := uuid.New()
	a := agentproto.Assignment{ID: uuid.New(), CertificateName: name, VersionID: &versionID,
		Files: []agentproto.FileSpec{{Path: p, Mode: "0644", SHA256: delivery.Digest(data)}}, Hooks: []agentproto.HookSpec{}}
	return a, agentproto.Bundle{VersionID: versionID, Files: []agentproto.BundleFile{{Path: p, Mode: "0644", Content: data}}}
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
			rep.Results[0].Installed[0].SHA256 != a.Files[0].SHA256 || rep.Results[0].VersionID != *a.VersionID {
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

// TestReconcileDoesNotRedeployOnDiskTamper is the ruling on I2: the agent
// is level-triggered on the assignment (version, redeploySeq, file list),
// never on-disk bytes, so a tampered file is left alone by Reconcile; the
// server learns about it (and, with auto-remediate, forces a redeploy by
// bumping redeploySeq) only from the digests this same reconcile reports.
func TestReconcileDoesNotRedeployOnDiskTamper(t *testing.T) {
	dir := t.TempDir()
	a, b := layoutGrant(dir, "web")
	api := &fakeAPI{as: agentproto.Assignments{Revision: 1, Grants: []agentproto.Assignment{a}}, bundles: map[uuid.UUID]agentproto.Bundle{a.ID: b}}
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}), ID: newTestIdentity(t), Log: discard}
	_, _ = r.Reconcile(context.Background())
	_ = os.WriteFile(a.Files[0].Path, []byte("tampered"), 0o644)
	rep, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(a.Files[0].Path)
	if api.fetched != 1 || string(got) != "tampered" {
		t.Fatalf("on-disk tamper redeployed: fetched %d content %q", api.fetched, got)
	}
	// The mismatched digest is still what gets reported, so the server can
	// still notice and mark drift even though the agent did not redeploy.
	if len(rep.Results) != 1 || rep.Results[0].State != agentproto.StateOK ||
		rep.Results[0].Installed[0].SHA256 == a.Files[0].SHA256 {
		t.Fatalf("report %+v", rep.Results)
	}
}

// TestReconcileRedeploysOnRedeploySeqBump: a bumped redeploySeq (an explicit
// Redeploy, or server-side auto-remediation) forces a redeploy even when
// the version and rendered file list are unchanged.
func TestReconcileRedeploysOnRedeploySeqBump(t *testing.T) {
	dir := t.TempDir()
	a, b := layoutGrant(dir, "web")
	// A harmless post_deploy hook, so a redeploy's hook re-run is
	// observable in the report.
	a.Hooks = []agentproto.HookSpec{{ID: uuid.New(), Phase: "post_deploy", Argv: []string{"/bin/sh", "-c", "exit 0"}, TimeoutSeconds: 5}}
	api := &fakeAPI{as: agentproto.Assignments{Revision: 1, Grants: []agentproto.Assignment{a}}, bundles: map[uuid.UUID]agentproto.Bundle{a.ID: b}}
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}, "/bin/sh"), ID: newTestIdentity(t), Log: discard}
	rep, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results[0].HookRuns) != 1 {
		t.Fatalf("first deploy did not run its post_deploy hook: %+v", rep.Results[0])
	}
	// An unchanged reconcile does not redeploy, so the hook does not re-run.
	rep, err = r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results[0].HookRuns) != 0 {
		t.Fatalf("hook re-ran on an unchanged reconcile: %+v", rep.Results[0])
	}
	_ = os.WriteFile(a.Files[0].Path, []byte("tampered"), 0o644)
	a.RedeploySeq = 1
	api.as = agentproto.Assignments{Revision: 2, Grants: []agentproto.Assignment{a}}
	rep, err = r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(a.Files[0].Path)
	if api.fetched != 2 || string(got) != "PEM-web" {
		t.Fatalf("redeploySeq bump did not redeploy: fetched %d content %q", api.fetched, got)
	}
	if len(rep.Results[0].HookRuns) != 1 {
		t.Fatalf("redeploySeq bump did not re-run the post_deploy hook: %+v", rep.Results[0])
	}
}

// TestReconcileKeepsOldFilesTrackedAfterFailedDeploy (residual fix wave): a
// failed deploy does not delete this grant's state outright. It keeps the
// previously written files tracked (marked Pending) so stale/orphan
// cleanup can still find and remove them once the assignment moves on,
// even though this particular attempt never confirmed a replacement; the
// next reconcile still retries regardless.
func TestReconcileKeepsOldFilesTrackedAfterFailedDeploy(t *testing.T) {
	dir := t.TempDir()
	a1, b1 := layoutGrant(dir, "web")
	api := &fakeAPI{as: agentproto.Assignments{Revision: 1, Grants: []agentproto.Assignment{a1}}, bundles: map[uuid.UUID]agentproto.Bundle{a1.ID: b1}}
	id := newTestIdentity(t)
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}, "/bin/sh"), ID: id, Log: discard}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldPath := a1.Files[0].Path
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatal("setup: old file not written")
	}
	// The path changes, and the new bundle's post_deploy hook fails after
	// the new file is actually written.
	newPath := filepath.Join(dir, "out", "web2.pem")
	data := []byte("PEM-web")
	a2 := agentproto.Assignment{ID: a1.ID, CertificateName: "web", VersionID: a1.VersionID,
		Files: []agentproto.FileSpec{{Path: newPath, Mode: "0644", SHA256: delivery.Digest(data)}},
		Hooks: []agentproto.HookSpec{{ID: uuid.New(), Phase: "post_deploy", Argv: []string{"/bin/sh", "-c", "exit 1"}, TimeoutSeconds: 5}}}
	b2 := agentproto.Bundle{VersionID: *a1.VersionID, Files: []agentproto.BundleFile{{Path: newPath, Mode: "0644", Content: data}}}
	api.as = agentproto.Assignments{Revision: 2, Grants: []agentproto.Assignment{a2}}
	api.bundles[a2.ID] = b2
	rep, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].State != agentproto.StateFailed {
		t.Fatalf("expected a failed report, got %+v", rep.Results)
	}
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatal("old file removed too early, before the new one was confirmed")
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatal("new file not written despite the failing post_deploy hook")
	}
	gs, ok := id.State.Grants[a1.ID]
	if !ok || !gs.Pending || len(gs.Files) != 1 || gs.Files[0].Path != oldPath {
		t.Fatalf("old file not tracked pending: ok=%v %+v", ok, gs)
	}
	// The next reconcile retries even though nothing about the assignment
	// changed since the last (failed) attempt: a third bundle fetch.
	if _, err := r.Reconcile(context.Background()); err != nil || api.fetched != 3 {
		t.Fatalf("did not retry the failed deploy: err=%v fetched=%d", err, api.fetched)
	}
	// Fix the hook; the deploy finally succeeds and cleans up the old,
	// now-stale file.
	a2.Hooks = nil
	api.as = agentproto.Assignments{Revision: 3, Grants: []agentproto.Assignment{a2}}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatal("old file not removed once the deploy finally succeeded")
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatal("new file missing after the successful deploy")
	}
	if gs := id.State.Grants[a1.ID]; gs.Pending {
		t.Fatal("state still marked pending after a successful deploy")
	}
}

// Review Focus (controller ruling on Task 8 concern 1, C3): an assignment
// with VersionID nil (a certificate with no version yet) is deployed
// straight from its Target's config — the Traefik ACME router file only —
// and Reconcile never calls Bundle for it (Bundle 404s "no issued version
// yet" server-side for exactly this case).
func TestReconcileDeploysVersionlessACMEFileWithoutBundle(t *testing.T) {
	dir := t.TempDir()
	tc := delivery.TraefikConfig{Dir: filepath.Join(dir, "traefik"), AcmeServiceURL: "http://agent:8080"}
	cfg, err := json.Marshal(tc)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"web.example.test"}
	acme := delivery.AcmeRouterFile("web", names, tc)
	if acme == nil {
		t.Fatal("setup: no ACME router file")
	}
	spec := agentproto.FileSpec{Path: acme.Path, Mode: acme.Mode, SHA256: delivery.Digest(acme.Data)}
	a := agentproto.Assignment{ID: uuid.New(), CertificateName: "web", CertificateNames: names, VersionID: nil,
		Files: []agentproto.FileSpec{spec}, Target: &agentproto.Target{Type: "traefik", Config: cfg}, Hooks: []agentproto.HookSpec{}}
	api := &fakeAPI{as: agentproto.Assignments{Revision: 1, Grants: []agentproto.Assignment{a}}}
	id := newTestIdentity(t)
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}), ID: id, Log: discard}

	rep, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if api.fetched != 0 {
		t.Fatalf("bundle fetched %d times, want 0", api.fetched)
	}
	if len(rep.Results) != 1 || rep.Results[0].State != agentproto.StateOK || rep.Results[0].VersionID != uuid.Nil || len(rep.Results[0].Installed) != 1 {
		t.Fatalf("report %+v", rep.Results)
	}
	if _, err := os.Stat(acme.Path); err != nil {
		t.Fatalf("ACME file not written: %v", err)
	}
	gs, ok := id.State.Grants[a.ID]
	if !ok || gs.VersionID != uuid.Nil || len(gs.Files) != 1 {
		t.Fatalf("state %+v", gs)
	}

	// A second, unchanged reconcile still never calls Bundle.
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.fetched != 0 {
		t.Fatalf("bundle fetched %d times on an unchanged reconcile, want 0", api.fetched)
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

// Review Focus: certsDir must come from Deploy's own return value, not be
// guessed back from file names. A layout (no target) whose files happen to
// be named privkey.pem/fullchain.pem must never have its directory pruned.
func TestReconcileNeverPrunesDirNamedLikeCertsFiles(t *testing.T) {
	dir := t.TempDir()
	admin := filepath.Join(dir, "admin")
	fullchain, privkey := filepath.Join(admin, "fullchain.pem"), filepath.Join(admin, "privkey.pem")
	data1, data2 := []byte("FULL"), []byte("KEY")
	a := agentproto.Assignment{ID: uuid.New(), CertificateName: "web", VersionID: verp(uuid.New()), Files: []agentproto.FileSpec{
		{Path: fullchain, Mode: "0644", SHA256: delivery.Digest(data1)},
		{Path: privkey, Mode: "0600", SHA256: delivery.Digest(data2)},
	}}
	b := agentproto.Bundle{VersionID: *a.VersionID, Files: []agentproto.BundleFile{
		{Path: fullchain, Mode: "0644", Content: data1},
		{Path: privkey, Mode: "0600", Content: data2},
	}}
	api := &fakeAPI{as: agentproto.Assignments{Revision: 1, Grants: []agentproto.Assignment{a}}, bundles: map[uuid.UUID]agentproto.Bundle{a.ID: b}}
	id := newTestIdentity(t)
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}), ID: id, Log: discard}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if id.State.Grants[a.ID].CertsDir != "" {
		t.Fatalf("CertsDir set for a layout grant with no target: %+v", id.State.Grants[a.ID])
	}
	api.as = agentproto.Assignments{Revision: 2, Removed: []agentproto.Removal{{ID: a.ID, Files: []string{fullchain, privkey}}}}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(admin); err != nil {
		t.Fatalf("admin dir pruned despite not being a Traefik target's certs dir: %v", err)
	}
}

// The exact certs/<name> directory Deploy created is pruned once its grant
// is removed.
func TestReconcileRemovalPrunesTargetCertsDir(t *testing.T) {
	dir := t.TempDir()
	a, b := traefikGrant(dir)
	api := &fakeAPI{as: agentproto.Assignments{Revision: 1, Grants: []agentproto.Assignment{a}}, bundles: map[uuid.UUID]agentproto.Bundle{a.ID: b}}
	id := newTestIdentity(t)
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}, "/bin/sh"), ID: id, Log: discard}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	certsDir := id.State.Grants[a.ID].CertsDir
	if certsDir == "" {
		t.Fatal("CertsDir not recorded for a Traefik-target grant")
	}
	api.as = agentproto.Assignments{Revision: 2, Removed: []agentproto.Removal{{ID: a.ID, Files: []string{}}}}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(certsDir); !os.IsNotExist(err) {
		t.Fatal("certs dir not pruned")
	}
}

// A partial write failure can leave state.json listing a file the server's
// removal message no longer names; removal unions both lists so it is still
// cleaned up.
func TestReconcileRemovalUnionsStateAndServerFileLists(t *testing.T) {
	dir := t.TempDir()
	a, b := layoutGrant(dir, "web")
	api := &fakeAPI{as: agentproto.Assignments{Revision: 1, Grants: []agentproto.Assignment{a}}, bundles: map[uuid.UUID]agentproto.Bundle{a.ID: b}}
	id := newTestIdentity(t)
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}), ID: id, Log: discard}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// state.json lists a second file the server's removal message omits
	// (simulating a leftover from an earlier partial write).
	leftover := filepath.Join(dir, "out", "leftover.pem")
	if err := os.WriteFile(leftover, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	gs := id.State.Grants[a.ID]
	gs.Files = append(gs.Files, agentproto.FileSpec{Path: leftover, Mode: "0644", SHA256: delivery.Digest([]byte("x"))})
	id.State.Grants[a.ID] = gs
	api.as = agentproto.Assignments{Revision: 2, Removed: []agentproto.Removal{{ID: a.ID, Files: []string{a.Files[0].Path}}}}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{a.Files[0].Path, leftover} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s not removed", p)
		}
	}
}

// An orphan (a grant in state.json the server no longer mentions at all)
// whose removal fails is reported as a failed result for its grant id.
func TestReconcileOrphanRemovalFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	a, b := layoutGrant(dir, "web")
	api := &fakeAPI{as: agentproto.Assignments{Revision: 1, Grants: []agentproto.Assignment{a}}, bundles: map[uuid.UUID]agentproto.Bundle{a.ID: b}}
	id := newTestIdentity(t)
	r := &Reconciler{API: api, Deployer: testDeployer([]string{dir}), ID: id, Log: discard}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.Deployer.WriteAllow = nil // every remove now refuses
	api.as = agentproto.Assignments{Revision: 2}
	rep, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].GrantID != a.ID || rep.Results[0].State != agentproto.StateFailed {
		t.Fatalf("report %+v", rep)
	}
	if _, ok := id.State.Grants[a.ID]; !ok {
		t.Fatal("orphan dropped from state despite a failed removal")
	}
}
