//go:build integration

package api

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
)

// enrolledWithGrant enrols an agent and grants it a current certificate
// through a one-file layout.
func (e *agentEnv) enrolledWithGrant(t *testing.T, name string, autoRemediate bool) (tls.Certificate, sqlcgen.Client, uuid.UUID) {
	t.Helper()
	en := e.newClient(t, name)
	cert, _, code := e.enroll(t, en.Token)
	if code != http.StatusOK {
		t.Fatalf("enroll %d", code)
	}
	certID, _ := e.currentCert(t, name+"-cert")
	layout := e.layout(t, name+"-layout", "/etc/ssl/"+name+".pem")
	gid, err := e.svc.CreateGrant(e.as("operator"), e.org, en.Client.ID, agents.GrantInput{CertID: certID, Delivery: "push", LayoutID: &layout, AutoRemediate: autoRemediate})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := e.q.GetClientByID(context.Background(), en.Client.ID)
	return cert, c, gid
}

func (e *agentEnv) deploymentState(t *testing.T, gid uuid.UUID) string {
	t.Helper()
	var s string
	if err := e.pool.QueryRow(context.Background(), `SELECT state FROM deployments WHERE grant_id = $1`, gid).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func okReport(as agentproto.Assignments) agentproto.Report {
	rep := agentproto.Report{Revision: as.Revision}
	for _, a := range as.Grants {
		res := agentproto.GrantResult{GrantID: a.ID, State: agentproto.StateOK}
		if a.VersionID != nil {
			res.VersionID = *a.VersionID
		}
		for _, f := range a.Files {
			res.Installed = append(res.Installed, agentproto.FileDigest{Path: f.Path, SHA256: f.SHA256})
		}
		rep.Results = append(rep.Results, res)
	}
	return rep
}

func TestAssignmentsBundleReport(t *testing.T) {
	e := newAgentEnv(t)
	cert, c, gid := e.enrolledWithGrant(t, "web-1", false)
	hc := e.httpClient(t, &cert)
	var as agentproto.Assignments
	if code := e.get(t, hc, "/agent/v1/assignments", &as); code != http.StatusOK || as.Revision != 1 || len(as.Grants) != 1 || len(as.Removed) != 0 {
		t.Fatalf("assignments %d %+v", code, as)
	}
	a := as.Grants[0]
	if a.ID != gid || a.CertificateName != "web-1-cert" || a.VersionID == nil || a.Fingerprint == "" || a.Target != nil || len(a.Files) != 1 || a.Files[0].Path != "/etc/ssl/web-1.pem" {
		t.Fatalf("assignment %+v", a)
	}
	var b agentproto.Bundle
	if code := e.get(t, hc, "/agent/v1/grants/"+gid.String()+"/bundle", &b); code != http.StatusOK || b.VersionID != *a.VersionID ||
		len(b.Files) != 1 || delivery.Digest(b.Files[0].Content) != a.Files[0].SHA256 || b.Material != nil {
		t.Fatalf("bundle %d %+v", code, b)
	}
	var actor string
	_ = e.pool.QueryRow(context.Background(), `SELECT actor_id FROM audit_events WHERE action = 'grant.bundle_fetched'`).Scan(&actor)
	if actor != c.ID.String() {
		t.Fatalf("bundle audit actor %q", actor)
	}
	for range 2 {
		if code := e.post(t, hc, "/agent/v1/report", okReport(as), nil); code != http.StatusNoContent {
			t.Fatalf("report %d", code)
		}
	}
	cl, _ := e.q.GetClientByID(context.Background(), c.ID)
	if e.deploymentState(t, gid) != "ok" || cl.AppliedRevision != 1 || e.auditCount(t, "deployment.ok") != 1 {
		t.Fatalf("state %s applied %d audits %d", e.deploymentState(t, gid), cl.AppliedRevision, e.auditCount(t, "deployment.ok"))
	}
}

func TestHeartbeatDriftAndRemediate(t *testing.T) {
	e := newAgentEnv(t)
	cert, c, gid := e.enrolledWithGrant(t, "web-1", true)
	hc := e.httpClient(t, &cert)
	var as agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &as)
	e.post(t, hc, "/agent/v1/report", okReport(as), nil)
	path := as.Grants[0].Files[0].Path
	bad := agentproto.Heartbeat{Installed: []agentproto.InstalledFile{{GrantID: gid, Path: path, SHA256: "0000", MTime: time.Now()}}}
	for range 2 {
		if code := e.post(t, hc, "/agent/v1/heartbeat", bad, nil); code != http.StatusNoContent {
			t.Fatalf("heartbeat %d", code)
		}
	}
	cl, _ := e.q.GetClientByID(context.Background(), c.ID)
	if e.deploymentState(t, gid) != "drift" || e.auditCount(t, "deployment.drift") != 1 || cl.DesiredRevision != 2 {
		t.Fatalf("drift: state %s audits %d rev %d", e.deploymentState(t, gid), e.auditCount(t, "deployment.drift"), cl.DesiredRevision)
	}
	msgs := e.hub.messages(c.ID)
	if len(msgs) != 2 || msgs[1] != agentproto.Message(agentproto.Sync{Revision: 2}) {
		t.Fatalf("remediation nudge %v", msgs)
	}
	var seq int64
	if err := e.pool.QueryRow(context.Background(), `SELECT redeploy_seq FROM client_cert_grants WHERE id = $1`, gid).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("auto-remediation did not bump redeploy_seq: %d", seq)
	}
	good := agentproto.Heartbeat{Installed: []agentproto.InstalledFile{{GrantID: gid, Path: path, SHA256: as.Grants[0].Files[0].SHA256, MTime: time.Now()}}}
	e.post(t, hc, "/agent/v1/heartbeat", good, nil)
	if e.deploymentState(t, gid) != "ok" || e.auditCount(t, "deployment.ok") != 2 {
		t.Fatalf("recovered: %s", e.deploymentState(t, gid))
	}
}

// TestHeartbeatDriftPersistsWithoutRemediate is the ruling on I2: without
// auto-remediate, an on-disk mismatch marks drift but never forces a
// redeploy (no redeploy_seq or revision bump) — the deployment stays
// drift until an operator calls Redeploy.
func TestHeartbeatDriftPersistsWithoutRemediate(t *testing.T) {
	e := newAgentEnv(t)
	cert, c, gid := e.enrolledWithGrant(t, "web-1", false)
	hc := e.httpClient(t, &cert)
	var as agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &as)
	e.post(t, hc, "/agent/v1/report", okReport(as), nil)
	path := as.Grants[0].Files[0].Path
	bad := agentproto.Heartbeat{Installed: []agentproto.InstalledFile{{GrantID: gid, Path: path, SHA256: "0000", MTime: time.Now()}}}
	for range 3 {
		if code := e.post(t, hc, "/agent/v1/heartbeat", bad, nil); code != http.StatusNoContent {
			t.Fatalf("heartbeat %d", code)
		}
	}
	cl, _ := e.q.GetClientByID(context.Background(), c.ID)
	if e.deploymentState(t, gid) != "drift" || e.auditCount(t, "deployment.drift") != 1 || cl.DesiredRevision != 1 {
		t.Fatalf("drift without remediate: state %s audits %d rev %d", e.deploymentState(t, gid), e.auditCount(t, "deployment.drift"), cl.DesiredRevision)
	}
	var seq int64
	if err := e.pool.QueryRow(context.Background(), `SELECT redeploy_seq FROM client_cert_grants WHERE id = $1`, gid).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if seq != 0 {
		t.Fatalf("redeploy_seq bumped without auto-remediate: %d", seq)
	}
	var as2 agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &as2)
	if as2.Revision != as.Revision {
		t.Fatalf("client nudged without auto-remediate: rev %d -> %d", as.Revision, as2.Revision)
	}
}

// TestRedeployForcesReinstall is the ruling on I2: Redeploy on an ok grant
// bumps redeploy_seq (so the agent's needsDeploy sees it as changed even
// though version and files are unchanged, forcing it to refetch the bundle,
// rewrite the files and re-run hooks) and resets the deployment to pending.
func TestRedeployForcesReinstall(t *testing.T) {
	e := newAgentEnv(t)
	cert, _, gid := e.enrolledWithGrant(t, "web-1", false)
	hc := e.httpClient(t, &cert)
	var as agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &as)
	e.post(t, hc, "/agent/v1/report", okReport(as), nil)
	if e.deploymentState(t, gid) != "ok" {
		t.Fatal("setup: deployment not ok")
	}
	if err := e.svc.Redeploy(e.as("operator"), e.org, gid); err != nil {
		t.Fatal(err)
	}
	if e.deploymentState(t, gid) != "pending" {
		t.Fatalf("redeploy did not reset the deployment to pending: %s", e.deploymentState(t, gid))
	}
	var as2 agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &as2)
	if as2.Grants[0].RedeploySeq != as.Grants[0].RedeploySeq+1 {
		t.Fatalf("redeploy did not bump redeploySeq: %d -> %d", as.Grants[0].RedeploySeq, as2.Grants[0].RedeploySeq)
	}
	if e.auditCount(t, "grant.redeploy") != 1 {
		t.Fatal("redeploy not audited")
	}
}

// Review Focus: an agent reaching beyond its own grants.
func TestBundleOtherClientGrant(t *testing.T) {
	e := newAgentEnv(t)
	certA, _, gidA := e.enrolledWithGrant(t, "web-a", false)
	certB, _, _ := e.enrolledWithGrant(t, "web-b", false)
	if code := e.get(t, e.httpClient(t, &certB), "/agent/v1/grants/"+gidA.String()+"/bundle", nil); code != http.StatusNotFound {
		t.Fatalf("other client's grant %d", code)
	}
	if code := e.get(t, e.httpClient(t, &certA), "/agent/v1/grants/not-a-uuid/bundle", nil); code != http.StatusNotFound {
		t.Fatalf("bad id %d", code)
	}
	if err := e.svc.DeleteGrant(e.as("operator"), e.org, gidA, false); err != nil {
		t.Fatal(err)
	}
	if code := e.get(t, e.httpClient(t, &certA), "/agent/v1/grants/"+gidA.String()+"/bundle", nil); code != http.StatusNotFound {
		t.Fatalf("removed grant %d", code)
	}
}

// Review Focus: late or foreign reports change nothing.
func TestReportStaleVersionIgnored(t *testing.T) {
	e := newAgentEnv(t)
	certA, _, gidA := e.enrolledWithGrant(t, "web-a", false)
	certB, _, _ := e.enrolledWithGrant(t, "web-b", false)
	stale := agentproto.Report{Revision: 1, Results: []agentproto.GrantResult{{GrantID: gidA, VersionID: uuid.New(), State: "ok",
		HookRuns: []agentproto.HookRun{{Phase: "post_deploy", Argv: []string{"/bin/true"}}}}}}
	e.post(t, e.httpClient(t, &certA), "/agent/v1/report", stale, nil)
	var as agentproto.Assignments
	e.get(t, e.httpClient(t, &certA), "/agent/v1/assignments", &as)
	e.post(t, e.httpClient(t, &certB), "/agent/v1/report", okReport(as), nil)
	if s := e.deploymentState(t, gidA); s != "pending" {
		t.Fatalf("state %s", s)
	}
	// The stale result's hook still ran on the host: it is history.
	var runs int
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM hook_runs WHERE grant_id = $1`, gidA).Scan(&runs)
	if runs != 1 || e.auditCount(t, "hook.run") != 1 {
		t.Fatalf("stale result's hook run not kept: rows %d audits %d", runs, e.auditCount(t, "hook.run"))
	}
}

// Review Focus: a deploy result from before the delete must not confirm
// the removal (the files are still on the host).
func TestRemovalNeedsRemovalResult(t *testing.T) {
	e := newAgentEnv(t)
	cert, _, gid := e.enrolledWithGrant(t, "web-1", false)
	hc := e.httpClient(t, &cert)
	var before agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &before)
	if err := e.svc.DeleteGrant(e.as("operator"), e.org, gid, false); err != nil {
		t.Fatal(err)
	}
	// The deploy result the agent computed from the pre-delete assignments.
	e.post(t, hc, "/agent/v1/report", okReport(before), nil)
	var as agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &as)
	if len(as.Removed) != 1 || as.Removed[0].ID != gid {
		t.Fatalf("grant no longer awaiting removal: %+v", as)
	}
	// A removal result from a revision before the delete does not count either.
	e.post(t, hc, "/agent/v1/report", agentproto.Report{Revision: before.Revision, Results: []agentproto.GrantResult{{GrantID: gid, State: "ok"}}}, nil)
	var n int
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM client_cert_grants WHERE id = $1`, gid).Scan(&n)
	if n != 1 {
		t.Fatal("stale removal result confirmed the removal")
	}
	e.post(t, hc, "/agent/v1/report", agentproto.Report{Revision: as.Revision, Results: []agentproto.GrantResult{{GrantID: gid, State: "ok"}}}, nil)
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM client_cert_grants WHERE id = $1`, gid).Scan(&n)
	if n != 0 {
		t.Fatal("removal result at the removal revision did not delete the grant")
	}
}

// Review Focus: hook_id is kept only for one of the grant's own hooks.
func TestHookRunKeepsOnlyGrantHooks(t *testing.T) {
	e := newAgentEnv(t)
	ctx := context.Background()
	cert, c, gid := e.enrolledWithGrant(t, "web-1", false)
	mine, err := e.q.CreateHook(ctx, sqlcgen.CreateHookParams{OrgID: e.org, Name: "mine", Phase: "post_deploy", Argv: []string{"/bin/true"}, TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.q.CreateHook(ctx, sqlcgen.CreateHookParams{OrgID: e.org, Name: "not-on-this-grant", Phase: "post_deploy", Argv: []string{"/bin/true"}, TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE client_cert_grants SET hook_ids = ARRAY[$2::uuid] WHERE id = $1`, gid, mine.ID); err != nil {
		t.Fatal(err)
	}
	hc := e.httpClient(t, &cert)
	var as agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &as)
	rep := okReport(as)
	rep.Results[0].HookRuns = []agentproto.HookRun{
		{HookID: mine.ID, Phase: "post_deploy", Argv: []string{"/bin/true"}},
		{HookID: other.ID, Phase: "post_deploy", Argv: []string{"/bin/true"}},
	}
	if code := e.post(t, hc, "/agent/v1/report", rep, nil); code != http.StatusNoContent {
		t.Fatalf("report %d", code)
	}
	res, err := e.srv.ListClientHookRuns(e.as("viewer"), gen.ListClientHookRunsRequestObject{OrgId: e.org, Id: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	runs := res.(gen.ListClientHookRuns200JSONResponse).Items
	names := map[string]int{}
	for _, r := range runs {
		names[r.HookName]++
	}
	if len(runs) != 2 || names["mine"] != 1 || names[""] != 1 {
		t.Fatalf("runs %+v", runs)
	}
}

func TestRemovedGrantConfirmed(t *testing.T) {
	e := newAgentEnv(t)
	cert, _, gid := e.enrolledWithGrant(t, "web-1", false)
	hc := e.httpClient(t, &cert)
	var before agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &before)
	if err := e.svc.DeleteGrant(e.as("operator"), e.org, gid, false); err != nil {
		t.Fatal(err)
	}
	var as agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &as)
	if len(as.Grants) != 0 || len(as.Removed) != 1 || as.Removed[0].ID != gid || as.Removed[0].Files[0] != before.Grants[0].Files[0].Path {
		t.Fatalf("assignments %+v", as)
	}
	e.post(t, hc, "/agent/v1/report", agentproto.Report{Revision: as.Revision, Results: []agentproto.GrantResult{{GrantID: gid, State: "ok"}}}, nil)
	var n int
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM client_cert_grants WHERE id = $1`, gid).Scan(&n)
	if n != 0 {
		t.Fatal("removed grant not deleted after confirmation")
	}
}

// TestReportRejectsUnknownHookPhase (M2): an unknown phase is rejected
// (logged, not stored) but does not stop the rest of the report — the
// deployment state and any other, valid hook run in the same result still
// land.
func TestReportRejectsUnknownHookPhase(t *testing.T) {
	e := newAgentEnv(t)
	cert, _, gid := e.enrolledWithGrant(t, "web-1", false)
	hc := e.httpClient(t, &cert)
	var as agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &as)
	rep := okReport(as)
	rep.Results[0].HookRuns = []agentproto.HookRun{
		{Phase: "bogus", Argv: []string{"/bin/true"}},
		{Phase: "post_deploy", Argv: []string{"/bin/true"}},
	}
	if code := e.post(t, hc, "/agent/v1/report", rep, nil); code != http.StatusNoContent {
		t.Fatalf("report %d", code)
	}
	if e.deploymentState(t, gid) != "ok" {
		t.Fatalf("deployment state %s", e.deploymentState(t, gid))
	}
	var runs int
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM hook_runs WHERE grant_id = $1`, gid).Scan(&runs)
	if runs != 1 {
		t.Fatalf("hook runs %d (want only the valid phase kept)", runs)
	}
}

func TestReportFailedAndHookRuns(t *testing.T) {
	e := newAgentEnv(t)
	cert, c, gid := e.enrolledWithGrant(t, "web-1", false)
	hc := e.httpClient(t, &cert)
	var as agentproto.Assignments
	e.get(t, hc, "/agent/v1/assignments", &as)
	rep := agentproto.Report{Revision: as.Revision, Results: []agentproto.GrantResult{{GrantID: gid, VersionID: *as.Grants[0].VersionID,
		State: "failed", Error: "pre_deploy hook /bin/false exited 1; files were not written",
		HookRuns: []agentproto.HookRun{{HookID: uuid.New(), Phase: "pre_deploy", Argv: []string{"/bin/false"}, ExitCode: 1,
			DurationMS: 3, Stdout: strings.Repeat("x", 9000), Stderr: "bad\x00byte"}}}}}
	if code := e.post(t, hc, "/agent/v1/report", rep, nil); code != http.StatusNoContent {
		t.Fatalf("report %d", code)
	}
	if e.deploymentState(t, gid) != "failed" || e.auditCount(t, "deployment.failed") != 1 || e.auditCount(t, "hook.run") != 1 {
		t.Fatal("failed report not recorded")
	}
	res, err := e.srv.ListClientHookRuns(e.as("viewer"), gen.ListClientHookRunsRequestObject{OrgId: e.org, Id: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	runs := res.(gen.ListClientHookRuns200JSONResponse).Items
	if len(runs) != 1 || runs[0].ExitCode != 1 || len(runs[0].Stdout) != 8192 || runs[0].HookId != nil || runs[0].Stderr != "badbyte" || runs[0].HookName != "" {
		t.Fatalf("runs %+v", runs)
	}
}
