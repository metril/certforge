//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/signer"
)

func push() gen.GrantDelivery { return gen.GrantDelivery("push") }

// Review Focus (final fix wave, I3): force skips waiting for the agent and
// hard-deletes a grant at once, whether it is still live or already
// removal-pending, audited with forced true.
func TestForceDeleteGrantSkipsWaitingOnAgent(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}})
	if err != nil {
		t.Fatal(err)
	}
	gid := res.(gen.CreateGrant201JSONResponse).Id
	force := true
	if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: gid, Params: gen.DeleteGrantParams{Force: &force}}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM client_cert_grants WHERE id = $1`, gid).Scan(&n)
	if n != 0 {
		t.Fatal("force delete did not hard-delete the still-live grant")
	}
	var details string
	_ = f.pool.QueryRow(context.Background(), `SELECT details::text FROM audit_events WHERE action = 'grant.delete' AND resource_id = $1`, gid.String()).Scan(&details)
	if !strings.Contains(details, `"forced": true`) {
		t.Fatalf("forced not audited: %s", details)
	}
}

// A removal-pending grant on a client that has since applied a revision
// (a plain, non-forced delete would wait for it to confirm the files are
// gone) is also hard-deleted at once by force.
func TestForceDeleteRemovalPendingGrant(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	c := f.activeClient(t, "web-1")
	if _, err := f.pool.Exec(context.Background(), `UPDATE clients SET applied_revision = 1 WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}})
	if err != nil {
		t.Fatal(err)
	}
	gid := res.(gen.CreateGrant201JSONResponse).Id
	if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: gid}); err != nil {
		t.Fatal(err)
	}
	var removed *time.Time
	_ = f.pool.QueryRow(context.Background(), `SELECT removed_at FROM client_cert_grants WHERE id = $1`, gid).Scan(&removed)
	if removed == nil {
		t.Fatal("setup: grant not removal-pending")
	}
	force := true
	if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: gid, Params: gen.DeleteGrantParams{Force: &force}}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM client_cert_grants WHERE id = $1`, gid).Scan(&n)
	if n != 0 {
		t.Fatal("force delete did not hard-delete the removal-pending grant")
	}
}

func TestGrantLifecycle(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	f.hub.online[c.ID] = true
	certID, vid := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateGrant201JSONResponse)
	d := g.Deployment
	if string(d.State) != "pending" || d.VersionId == nil || *d.VersionId != vid || len(d.Expected) != 1 || d.Expected[0].Path != "/etc/ssl/web.pem" {
		t.Fatalf("deployment %+v", d)
	}
	m, _ := f.certs.Material(ctx, certID, vid, true)
	files, _ := delivery.RenderLayout(m, []delivery.OutputFile{{Path: "/etc/ssl/web.pem", Format: "pem", Parts: []string{"fullchain"}, Mode: "0644"}})
	if d.Expected[0].Sha256 != delivery.Digest(files[0].Data) {
		t.Fatal("expected digest differs from the rendered file")
	}
	rev := func() int64 {
		cl, _ := f.q.GetClientByID(ctx, c.ID)
		return cl.DesiredRevision
	}
	if rev() != 1 || len(f.hub.messages(c.ID)) != 1 || f.hub.messages(c.ID)[0] != agentproto.Message(agentproto.Sync{Revision: 1}) {
		t.Fatalf("rev %d msgs %v", rev(), f.hub.messages(c.ID))
	}
	if _, err := f.srv.UpdateGrant(op, gen.UpdateGrantRequestObject{OrgId: f.org, Id: g.Id, Body: &gen.GrantUpdate{
		Delivery: gen.GrantDelivery("pull"), LayoutId: &layout, HookIds: []uuid.UUID{}, AutoRemediate: true}}); err != nil {
		t.Fatal(err)
	}
	if rev() != 2 || len(f.hub.messages(c.ID)) != 1 {
		t.Fatalf("pull update: rev %d msgs %d", rev(), len(f.hub.messages(c.ID)))
	}
	if _, err := f.srv.RedeployGrant(op, gen.RedeployGrantRequestObject{OrgId: f.org, Id: g.Id}); err != nil {
		t.Fatal(err)
	}
	if rev() != 3 || len(f.hub.messages(c.ID)) != 1 {
		t.Fatalf("redeploy of a pull grant nudged: rev %d msgs %d", rev(), len(f.hub.messages(c.ID)))
	}
	lg, _ := f.srv.ListClientGrants(f.as("viewer"), gen.ListClientGrantsRequestObject{OrgId: f.org, Id: c.ID})
	if items := lg.(gen.ListClientGrants200JSONResponse).Items; len(items) != 1 || !items[0].AutoRemediate || items[0].CertificateName != "web" {
		t.Fatalf("grants %+v", items)
	}
	cd, err := f.srv.ListCertificateDeployments(f.as("viewer"), gen.ListCertificateDeploymentsRequestObject{OrgId: f.org, Id: certID})
	if err != nil || len(cd.(gen.ListCertificateDeployments200JSONResponse).Items) != 1 || !cd.(gen.ListCertificateDeployments200JSONResponse).Items[0].ClientConnected {
		t.Fatalf("deployments %v %v", cd, err)
	}
	if row := cd.(gen.ListCertificateDeployments200JSONResponse).Items[0]; row.LayoutId == nil || *row.LayoutId != layout ||
		row.LayoutName == nil || *row.LayoutName != "pem" || row.DeployTargetId != nil || row.DeployTargetName != nil {
		t.Fatalf("deployment layout/target %+v", row)
	}
	if !cd.(gen.ListCertificateDeployments200JSONResponse).Items[0].ClientOnline {
		t.Fatal("a connected client must be online")
	}
	lc, err := f.srv.ListCertificates(f.as("viewer"), gen.ListCertificatesRequestObject{OrgId: f.org})
	if err != nil || *lc.(gen.ListCertificates200JSONResponse).Items[0].GrantCount != 1 {
		t.Fatalf("grant count %v %v", lc, err)
	}
	_, err = f.srv.DeleteCertificate(op, gen.DeleteCertificateRequestObject{OrgId: f.org, Id: certID})
	wantStatus(t, err, 409)
	if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: g.Id}); err != nil {
		t.Fatal(err)
	}
	var removed *time.Time
	_ = f.pool.QueryRow(ctx, `SELECT removed_at FROM client_cert_grants WHERE id = $1`, g.Id).Scan(&removed)
	if removed == nil || rev() != 4 {
		t.Fatalf("soft delete: removed %v rev %d", removed, rev())
	}
	if lg, _ := f.srv.ListClientGrants(op, gen.ListClientGrantsRequestObject{OrgId: f.org, Id: c.ID}); len(lg.(gen.ListClientGrants200JSONResponse).Items) != 0 {
		t.Fatal("removed grant still listed")
	}
	var details string
	_ = f.pool.QueryRow(ctx, `SELECT details::text FROM audit_events WHERE action = 'grant.update'`).Scan(&details)
	for _, a := range []string{"grant.create", "grant.update", "grant.redeploy", "grant.delete"} {
		if f.auditCount(t, a) != 1 {
			t.Errorf("audit %s = %d", a, f.auditCount(t, a))
		}
	}
	if !strings.Contains(details, `"before"`) || !strings.Contains(details, `"pull"`) {
		t.Fatalf("update details %s", details)
	}
}

func TestGrantOnPendingClientDeletesAtOnce(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	c := f.newClient(t, "web-1").Client
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}})
	if err != nil {
		t.Fatal(err)
	}
	id := res.(gen.CreateGrant201JSONResponse).Id
	if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: id}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM client_cert_grants WHERE id = $1`, id).Scan(&n)
	if n != 0 {
		t.Fatal("grant of a never-enrolled client kept for removal")
	}
}

// Review Focus: cross-org references in a grant.
func TestGrantRejectsCrossOrgReferences(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	other := dbtest.Org(t, f.pool)
	oc, err := f.store.CreateCertificate(ctx, other, issuance.CertInput{Name: "theirs", CommonName: "theirs.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	files, _ := json.Marshal([]delivery.OutputFile{{Path: "/x.pem", Format: "pem", Parts: []string{"cert"}, Mode: "0644"}})
	ol, _ := f.q.CreateLayout(ctx, sqlcgen.CreateLayoutParams{OrgID: other, Name: "theirs", Files: files})
	oh, _ := f.q.CreateHook(ctx, sqlcgen.CreateHookParams{OrgID: other, Name: "theirs", Phase: "post_deploy", Argv: []string{"/bin/true"}, TimeoutSeconds: 60})
	for name, in := range map[string]gen.GrantInput{
		"cert":     {CertificateId: oc.ID, Delivery: push(), LayoutId: &layout},
		"layout":   {CertificateId: certID, Delivery: push(), LayoutId: &ol.ID},
		"hook":     {CertificateId: certID, Delivery: push(), LayoutId: &layout, HookIds: &[]uuid.UUID{oh.ID}},
		"neither":  {CertificateId: certID, Delivery: push()},
		"delivery": {CertificateId: certID, Delivery: gen.GrantDelivery("email"), LayoutId: &layout},
	} {
		body := in
		_, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &body})
		if problemStatus(err) != 422 {
			t.Errorf("%s: %v", name, err)
		}
	}
	good := gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &good}); err != nil {
		t.Fatal(err)
	}
	_, err = f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &good})
	wantStatus(t, err, 409)
	var n int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM client_cert_grants`).Scan(&n)
	if n != 1 {
		t.Fatalf("grants stored %d", n)
	}
}

func TestLayoutUpdateResyncsAndDeleteBlocked(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: layout, Body: layoutInput("pem", "/etc/ssl/moved.pem")}); err != nil {
		t.Fatal(err)
	}
	var expected string
	var rev int64
	_ = f.pool.QueryRow(ctx, `SELECT d.expected::text, c.desired_revision FROM deployments d JOIN client_cert_grants g ON g.id = d.grant_id JOIN clients c ON c.id = g.client_id`).Scan(&expected, &rev)
	if !strings.Contains(expected, "/etc/ssl/moved.pem") || rev != 2 {
		t.Fatalf("expected %s rev %d", expected, rev)
	}
	_, err := f.srv.DeleteLayout(op, gen.DeleteLayoutRequestObject{OrgId: f.org, Id: layout})
	wantStatus(t, err, 409)
	var he *HTTPError
	if !errors.As(err, &he) || !strings.Contains(he.Detail, "web-1/web") {
		t.Fatalf("err %v", err)
	}
}

// Two grants on one client never write the same path.
func TestGrantRejectsOverlappingPaths(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	upper, _ := f.currentCert(t, "Web")
	lower, _ := f.currentCert(t, "web")
	api, _ := f.currentCert(t, "api")
	tg, err := f.q.CreateDeployTarget(ctx, sqlcgen.CreateDeployTargetParams{OrgID: f.org, Name: "traefik", Type: "traefik",
		Config: []byte(`{"dir":"/etc/traefik/dynamic"}`)})
	if err != nil {
		t.Fatal(err)
	}
	create := func(cert uuid.UUID, in gen.GrantInput) (uuid.UUID, error) {
		in.CertificateId, in.Delivery = cert, push()
		res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &in})
		if err != nil {
			return uuid.Nil, err
		}
		return res.(gen.CreateGrant201JSONResponse).Id, nil
	}
	if _, err := create(upper, gen.GrantInput{DeployTargetId: &tg.ID}); err != nil {
		t.Fatal(err)
	}
	_, err = create(lower, gen.GrantInput{DeployTargetId: &tg.ID}) // "Web" and "web" share certs/web/*
	wantStatus(t, err, 409)
	shared := f.layout(t, "shared", "/etc/ssl/shared.pem")
	first, err := create(api, gen.GrantInput{LayoutId: &shared})
	if err != nil {
		t.Fatal(err)
	}
	_, err = create(lower, gen.GrantInput{LayoutId: &shared})
	wantStatus(t, err, 409)
	if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: first}); err != nil {
		t.Fatal(err)
	}
	_, err = create(lower, gen.GrantInput{LayoutId: &shared}) // still awaiting agent removal
	wantStatus(t, err, 409)
	own := f.layout(t, "own", "/etc/ssl/own.pem")
	if _, err := create(lower, gen.GrantInput{LayoutId: &own}); err != nil {
		t.Fatal(err)
	}
	_, err = f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: own,
		Body: layoutInput("own", "/etc/traefik/dynamic/certs/web/fullchain.pem")})
	wantStatus(t, err, 409)
	var files string
	_ = f.pool.QueryRow(ctx, `SELECT files::text FROM output_specs WHERE id = $1`, own).Scan(&files)
	if !strings.Contains(files, "/etc/ssl/own.pem") {
		t.Fatalf("refused layout update committed: %s", files)
	}
}

// Review Focus: a concurrent grant create and hook delete must never leave a
// grant referencing a hook id that no longer exists (hook_ids has no FK).
func TestGrantVsDeleteHookNoDangling(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	for i := 0; i < 10; i++ {
		h, err := f.q.CreateHook(ctx, sqlcgen.CreateHookParams{OrgID: f.org, Name: "h", Phase: "post_deploy", Argv: []string{"/bin/true"}, TimeoutSeconds: 60})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var createErr, deleteErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, createErr = f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
				Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout, HookIds: &[]uuid.UUID{h.ID}}})
		}()
		go func() {
			defer wg.Done()
			_, deleteErr = f.srv.DeleteHook(op, gen.DeleteHookRequestObject{OrgId: f.org, Id: h.ID})
		}()
		wg.Wait()
		if createErr == nil && deleteErr == nil {
			t.Fatalf("iteration %d: both the grant create and the hook delete succeeded", i)
		}
		var dangling int
		_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM client_cert_grants g WHERE $1 = ANY(g.hook_ids)
			AND NOT EXISTS (SELECT 1 FROM hooks h WHERE h.id = $1)`, h.ID).Scan(&dangling)
		if dangling > 0 {
			t.Fatalf("iteration %d: a grant references hook %s which no longer exists", i, h.ID)
		}
		if createErr == nil {
			// Free the client for the next iteration's grant on the same cert.
			var gid uuid.UUID
			_ = f.pool.QueryRow(ctx, `SELECT id FROM client_cert_grants WHERE cert_id = $1 AND client_id = $2`, certID, c.ID).Scan(&gid)
			if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: gid}); err != nil {
				t.Fatal(err)
			}
		}
		// Whichever side won, free the hook's name for the next iteration:
		// on a create win, DeleteHook lost and the hook is still there
		// (its only dependent, the grant above, is now gone, so this is
		// safe); on a delete win it is a no-op.
		if _, err := f.pool.Exec(ctx, `DELETE FROM hooks WHERE id = $1`, h.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOnVersionUpdatesDeployments(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	f.hub.online[c.ID] = true
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}}); err != nil {
		t.Fatal(err)
	}
	tx, _ := f.store.Begin(ctx)
	v2, err := f.certs.Insert(ctx, tx, certID, &signer.Issued{LeafDER: []byte("leaf2"), ChainDER: [][]byte{[]byte("int")},
		PrivateKeyPKCS8: []byte("secret-key-2"), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Serial: "02"}, "ec256", certstore.InsertOpts{Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE certificates SET current_version_id = $2 WHERE id = $1`, certID, v2.ID); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	f.svc.OnVersion(ctx, certID, v2.ID)
	var got uuid.UUID
	var state string
	_ = f.pool.QueryRow(ctx, `SELECT version_id, state FROM deployments`).Scan(&got, &state)
	cl, _ := f.q.GetClientByID(ctx, c.ID)
	if got != v2.ID || state != "pending" || cl.DesiredRevision != 2 || len(f.hub.messages(c.ID)) != 2 {
		t.Fatalf("version %v state %s rev %d msgs %d", got, state, cl.DesiredRevision, len(f.hub.messages(c.ID)))
	}
	// A version whose OnVersion never ran is picked up by the hourly sweep.
	tx, _ = f.store.Begin(ctx)
	v3, err := f.certs.Insert(ctx, tx, certID, &signer.Issued{LeafDER: []byte("leaf3"), ChainDER: [][]byte{[]byte("int")},
		PrivateKeyPKCS8: []byte("secret-key-3"), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Serial: "03"}, "ec256", certstore.InsertOpts{Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE certificates SET current_version_id = $2 WHERE id = $1`, certID, v3.ID); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	if err := f.svc.SweepDeployments(ctx); err != nil {
		t.Fatal(err)
	}
	_ = f.pool.QueryRow(ctx, `SELECT version_id FROM deployments`).Scan(&got)
	if cl, _ = f.q.GetClientByID(ctx, c.ID); got != v3.ID || cl.DesiredRevision != 3 {
		t.Fatalf("sweep: version %v rev %d", got, cl.DesiredRevision)
	}
	if err := f.svc.SweepDeployments(ctx); err != nil {
		t.Fatal(err)
	}
	if cl, _ = f.q.GetClientByID(ctx, c.ID); cl.DesiredRevision != 3 {
		t.Fatal("a sweep with nothing stale bumped the revision")
	}
}

// Review Focus (fix round 1, finding 1): a layout update (resyncTx) and a
// grant create on the same client take client and deployment locks; before
// the fix they took them in opposite orders (resyncTx: deployment then
// client; CreateGrant: client then deployment) and could deadlock (a 500),
// and checkPaths could run before the affected client was locked. Now
// render locks the affected clients first, so the two requests serialize:
// whichever proceeds first commits, and the other sees its result and
// fails with 409 — never a 500, and never both succeeding when their
// results genuinely collide.
func TestConcurrentLayoutUpdateVsGrantCreateNoDeadlock(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	certA, _ := f.currentCert(t, "a")
	certB, _ := f.currentCert(t, "b")
	l1 := f.layout(t, "l1", "/a.pem")
	l2 := f.layout(t, "l2", "/b.pem")
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certA, Delivery: push(), LayoutId: &l1}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		// Reset l1 back to its own path and remove any grant on certB from
		// a previous iteration, so each iteration starts from the same
		// unconflicted state and the race is exercised fresh each time.
		if _, err := f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: l1, Body: layoutInput("l1", "/a.pem")}); err != nil {
			t.Fatal(err)
		}
		var gid *uuid.UUID
		_ = f.pool.QueryRow(ctx, `SELECT id FROM client_cert_grants WHERE client_id = $1 AND cert_id = $2`, c.ID, certB).Scan(&gid)
		if gid != nil {
			if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: *gid}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.pool.Exec(ctx, `DELETE FROM client_cert_grants WHERE id = $1`, *gid); err != nil {
				t.Fatal(err)
			}
		}
		var wg sync.WaitGroup
		var updErr, createErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, updErr = f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: l1, Body: layoutInput("l1", "/b.pem")})
		}()
		go func() {
			defer wg.Done()
			_, createErr = f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certB, Delivery: push(), LayoutId: &l2}})
		}()
		wg.Wait()
		for _, err := range []error{updErr, createErr} {
			if err != nil && problemStatus(err) == 500 {
				t.Fatalf("iteration %d: got a 500: %v", i, err)
			}
		}
		if updErr == nil && createErr == nil {
			t.Fatalf("iteration %d: both succeeded; overlapping /b.pem not detected", i)
		}
		if updErr != nil {
			wantStatus(t, updErr, 409)
		}
		if createErr != nil {
			wantStatus(t, createErr, 409)
		}
	}
}

// Review Focus (fix round 1, finding 2): DeleteCertificate must lock the
// certificate and count removal-pending grants too (cert_id is ON DELETE
// CASCADE), and CreateGrant must lock the certificate so it cannot insert a
// grant for a certificate a concurrent delete is removing.
func TestDeleteCertificateBlockedByRemovalPendingGrant(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}})
	if err != nil {
		t.Fatal(err)
	}
	gid := res.(gen.CreateGrant201JSONResponse).Id
	if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: gid}); err != nil {
		t.Fatal(err)
	}
	var removed *time.Time
	_ = f.pool.QueryRow(ctx, `SELECT removed_at FROM client_cert_grants WHERE id = $1`, gid).Scan(&removed)
	if removed == nil {
		t.Fatal("setup: grant not removal-pending")
	}
	_, err = f.srv.DeleteCertificate(op, gen.DeleteCertificateRequestObject{OrgId: f.org, Id: certID})
	wantStatus(t, err, 409)
	var n int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE id = $1`, certID).Scan(&n)
	if n != 1 {
		t.Fatal("certificate deleted despite a removal-pending grant")
	}
}

func TestConcurrentCreateGrantVsDeleteCertificateNoDangling(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	for i := 0; i < 10; i++ {
		certID, _ := f.currentCert(t, fmt.Sprintf("web-%d", i))
		var wg sync.WaitGroup
		var createErr, deleteErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, createErr = f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}})
		}()
		go func() {
			defer wg.Done()
			_, deleteErr = f.srv.DeleteCertificate(op, gen.DeleteCertificateRequestObject{OrgId: f.org, Id: certID})
		}()
		wg.Wait()
		for _, err := range []error{createErr, deleteErr} {
			if err != nil && problemStatus(err) == 500 {
				t.Fatalf("iteration %d: got a 500: %v", i, err)
			}
		}
		var orphan int
		_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM client_cert_grants g WHERE g.cert_id = $1
			AND NOT EXISTS (SELECT 1 FROM certificates ce WHERE ce.id = $1)`, certID).Scan(&orphan)
		if orphan > 0 {
			t.Fatalf("iteration %d: a grant references certificate %s which no longer exists", i, certID)
		}
		// Clean up whichever side won, so the next iteration starts clean.
		if createErr == nil {
			var gid uuid.UUID
			if err := f.pool.QueryRow(ctx, `SELECT id FROM client_cert_grants WHERE cert_id = $1`, certID).Scan(&gid); err == nil {
				if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: gid}); err != nil {
					t.Fatal(err)
				}
				_, _ = f.pool.Exec(ctx, `DELETE FROM client_cert_grants WHERE id = $1`, gid)
			}
		}
		if deleteErr == nil || createErr == nil {
			_, _ = f.pool.Exec(ctx, `DELETE FROM certificates WHERE id = $1`, certID)
		}
	}
}

// Review Focus (final fix wave, I1): LockLayoutForGrant/LockTargetForGrant
// used to take FOR KEY SHARE, which Postgres treats as compatible with the
// FOR NO KEY UPDATE an UPDATE statement takes implicitly (UpdateLayout): the
// two locks never actually conflicted, so a layout PATCH and a CreateGrant
// referencing the same layout could run unaware of each other, and a grant
// created while the PATCH's own Resync had already read its pre-update list
// of live grants could be left rendered from the pre-update layout forever.
// FOR SHARE does conflict with FOR NO KEY UPDATE, forcing the two to
// serialize: whichever commits first is either what the other renders from
// directly, or is what Resync re-renders once it commits second.
func TestConcurrentLayoutUpdateVsGrantCreateSameLayoutNeverStale(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	l1 := f.layout(t, "l1", "/a.pem")
	for i := 0; i < 10; i++ {
		if _, err := f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: l1, Body: layoutInput("l1", "/a.pem")}); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var updErr, createErr error
		var gid uuid.UUID
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, updErr = f.srv.UpdateLayout(op, gen.UpdateLayoutRequestObject{OrgId: f.org, Id: l1, Body: layoutInput("l1", "/b.pem")})
		}()
		go func() {
			defer wg.Done()
			res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &l1}})
			createErr = err
			if err == nil {
				gid = res.(gen.CreateGrant201JSONResponse).Id
			}
		}()
		wg.Wait()
		if updErr != nil {
			t.Fatalf("iteration %d: layout update failed: %v", i, updErr)
		}
		if createErr != nil {
			t.Fatalf("iteration %d: grant create failed: %v", i, createErr)
		}
		var expected []byte
		if err := f.pool.QueryRow(ctx, `SELECT expected FROM deployments WHERE grant_id = $1`, gid).Scan(&expected); err != nil {
			t.Fatal(err)
		}
		var specs []agentproto.FileSpec
		if err := json.Unmarshal(expected, &specs); err != nil {
			t.Fatal(err)
		}
		if len(specs) != 1 || specs[0].Path != "/b.pem" {
			t.Fatalf("iteration %d: stale expected %+v", i, specs)
		}
		if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: gid}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(ctx, `DELETE FROM client_cert_grants WHERE id = $1`, gid); err != nil {
			t.Fatal(err)
		}
	}
}

// Review Focus (fix round 1, finding 3): a render failure for one client
// (a corrupted deploy target config) must not stop another client's
// deployment from being updated by the same OnVersion/SweepDeployments run.
func TestOnVersionIsolatesPerClientRenderFailure(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	good := f.activeClient(t, "web-good")
	bad := f.activeClient(t, "web-bad")
	certID, vid := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: good.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}}); err != nil {
		t.Fatal(err)
	}
	tg, err := f.q.CreateDeployTarget(ctx, sqlcgen.CreateDeployTargetParams{OrgID: f.org, Name: "traefik", Type: "traefik",
		Config: []byte(`{"dir":"/etc/traefik/dynamic"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: bad.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), DeployTargetId: &tg.ID}}); err != nil {
		t.Fatal(err)
	}
	// Corrupt the bad client's target config directly so ParseTarget fails
	// deterministically on every render of that grant.
	if _, err := f.pool.Exec(ctx, `UPDATE deploy_targets SET config = '{"dir":123}' WHERE id = $1`, tg.ID); err != nil {
		t.Fatal(err)
	}
	tx, _ := f.store.Begin(ctx)
	v2, err := f.certs.Insert(ctx, tx, certID, &signer.Issued{LeafDER: []byte("leaf2"), ChainDER: [][]byte{[]byte("int")},
		PrivateKeyPKCS8: []byte("secret-key-2"), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Serial: "02"}, "ec256", certstore.InsertOpts{Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE certificates SET current_version_id = $2 WHERE id = $1`, certID, v2.ID); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	f.svc.OnVersion(ctx, certID, v2.ID)
	var gotGood uuid.UUID
	_ = f.pool.QueryRow(ctx, `SELECT d.version_id FROM deployments d JOIN client_cert_grants g ON g.id = d.grant_id WHERE g.client_id = $1`, good.ID).Scan(&gotGood)
	if gotGood != v2.ID {
		t.Fatalf("good client's deployment not updated despite the bad client's render failure: got %v want %v", gotGood, v2.ID)
	}
	var gotBad uuid.UUID
	_ = f.pool.QueryRow(ctx, `SELECT d.version_id FROM deployments d JOIN client_cert_grants g ON g.id = d.grant_id WHERE g.client_id = $1`, bad.ID).Scan(&gotBad)
	if gotBad != vid {
		t.Fatalf("bad client's deployment should be left at the old version after its render failed: got %v want %v", gotBad, vid)
	}
	// The sweep re-attempts the bad client's stale grant (and fails again)
	// without erroring out before updating anything: nothing further to
	// assert here beyond it not panicking or deadlocking.
	_ = f.svc.SweepDeployments(ctx)
}

// Review Focus (fix round 1, finding 4a): a removal-pending grant whose
// deployment was never rendered (expected == "[]", because its certificate
// had no current version yet) must still contribute its layout's path to
// the overlap check, not silently contribute zero paths.
func TestGrantRejectsOverlappingPathWithUnrenderedRemovedGrant(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	certA, err := f.store.CreateCertificate(ctx, f.org, issuance.CertInput{Name: "a", CommonName: "a.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	certB, _ := f.currentCert(t, "b")
	shared := f.layout(t, "shared", "/etc/ssl/shared.pem")
	// certA has no issued version yet, so this grant's deployment renders
	// with expected == "[]".
	res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certA.ID, Delivery: push(), LayoutId: &shared}})
	if err != nil {
		t.Fatal(err)
	}
	gid := res.(gen.CreateGrant201JSONResponse).Id
	var expected string
	_ = f.pool.QueryRow(ctx, `SELECT expected::text FROM deployments WHERE grant_id = $1`, gid).Scan(&expected)
	if expected != "[]" {
		t.Fatalf("setup: expected %s, want an empty render", expected)
	}
	if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: gid}); err != nil {
		t.Fatal(err)
	}
	var removed *time.Time
	_ = f.pool.QueryRow(ctx, `SELECT removed_at FROM client_cert_grants WHERE id = $1`, gid).Scan(&removed)
	if removed == nil {
		t.Fatal("setup: grant not removal-pending")
	}
	_, err = f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certB, Delivery: push(), LayoutId: &shared}})
	wantStatus(t, err, 409)
}

// Review Focus (fix round 1, finding 4b): renaming a certificate that has
// live grants re-checks overlapping Traefik paths (certs/<SafeName>
// depends on the name) and re-renders those grants in the same
// transaction as the rename.
func TestCertificateRenameResyncsGrantsAndBlocksOverlap(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	apiCert, _ := f.currentCert(t, "api")
	webCert, _ := f.currentCert(t, "web")
	tg, err := f.q.CreateDeployTarget(ctx, sqlcgen.CreateDeployTargetParams{OrgID: f.org, Name: "traefik", Type: "traefik",
		Config: []byte(`{"dir":"/etc/traefik/dynamic"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: apiCert, Delivery: push(), DeployTargetId: &tg.ID}}); err != nil {
		t.Fatal(err)
	}
	webGrant, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: webCert, Delivery: push(), DeployTargetId: &tg.ID}})
	if err != nil {
		t.Fatal(err)
	}
	rev := func() int64 {
		cl, _ := f.q.GetClientByID(ctx, c.ID)
		return cl.DesiredRevision
	}
	before := rev()
	// Renaming "web" to "API" collides with the existing "api" grant's
	// Traefik certs/api/* paths on the same client (SafeName lowercases,
	// so "API" and "api" share certs/api/*); the literal names still
	// differ, so this isn't blocked by the name-uniqueness constraint.
	_, err = f.srv.UpdateCertificate(op, gen.UpdateCertificateRequestObject{OrgId: f.org, Id: webCert,
		Body: &gen.CertificateInput{Name: "API", CommonName: "web.example.test"}})
	wantStatus(t, err, 409)
	var stillWeb string
	_ = f.pool.QueryRow(ctx, `SELECT name FROM certificates WHERE id = $1`, webCert).Scan(&stillWeb)
	if stillWeb != "web" {
		t.Fatalf("rename committed despite the overlap: name is now %q", stillWeb)
	}
	if rev() != before {
		t.Fatalf("a rejected rename bumped the revision: %d -> %d", before, rev())
	}
	// A non-colliding rename succeeds, re-renders the grant under the new
	// name, and bumps the revision.
	if _, err := f.srv.UpdateCertificate(op, gen.UpdateCertificateRequestObject{OrgId: f.org, Id: webCert,
		Body: &gen.CertificateInput{Name: "website", CommonName: "web.example.test"}}); err != nil {
		t.Fatal(err)
	}
	var expected string
	_ = f.pool.QueryRow(ctx, `SELECT expected::text FROM deployments WHERE grant_id = $1`, webGrant.(gen.CreateGrant201JSONResponse).Id).Scan(&expected)
	if !strings.Contains(expected, "certs/website/") {
		t.Fatalf("deployment not re-rendered under the new name: %s", expected)
	}
	if rev() != before+1 {
		t.Fatalf("successful rename did not bump the revision once: before %d now %d", before, rev())
	}
}

// Review Focus (fix round 1, ruling 5): DeleteGrant only hard-deletes at
// once for a client that could never have deployed anything (revoked, or
// pending with applied_revision 0). A client that re-enrolled (dropped
// back to pending) after actually applying a revision may still have this
// grant's files on disk, so it keeps the soft-delete path.
func TestDeleteGrantSoftDeletesReenrolledClientThatHadDeployed(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}})
	if err != nil {
		t.Fatal(err)
	}
	gid := res.(gen.CreateGrant201JSONResponse).Id
	// Simulate a client that applied a revision and then re-enrolled
	// (dropped back to pending without resetting applied_revision).
	if _, err := f.pool.Exec(ctx, `UPDATE clients SET status = 'pending', applied_revision = 1 WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: gid}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM client_cert_grants WHERE id = $1`, gid).Scan(&n)
	if n != 1 {
		t.Fatal("grant of a re-enrolled, previously-deployed client hard-deleted instead of soft-deleted")
	}
	var removed *time.Time
	_ = f.pool.QueryRow(ctx, `SELECT removed_at FROM client_cert_grants WHERE id = $1`, gid).Scan(&removed)
	if removed == nil {
		t.Fatal("grant not marked removal-pending")
	}
}

// Fix round 2: CreateGrant/UpdateGrant must lock referenced rows (hooks,
// layout, deploy target, certificate) before the client row, the same order
// a hook/layout/target update or a certificate rename uses (its own row,
// then affected clients via Resync/render). Before the fix, CreateGrant
// locked the client first and the hook second: a concurrent hook update
// (hook row, then the client via Resync) and a concurrent CreateGrant on a
// client already using that hook (client, then the hook FOR SHARE) lock the
// same two rows in opposite order, an AB-BA deadlock Postgres reports as a
// 500. With the fix both lock hook-before-client, so they only serialize.
func TestConcurrentHookUpdateVsCreateGrantNoDeadlock(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	sixty := 60
	hRes, err := f.srv.CreateHook(op, gen.CreateHookRequestObject{OrgId: f.org,
		Body: &gen.HookInput{Name: "reload", Phase: gen.HookPhase("post_deploy"), Argv: []string{"/bin/true"}, TimeoutSeconds: &sixty}})
	if err != nil {
		t.Fatal(err)
	}
	h := hRes.(gen.CreateHook201JSONResponse)
	cert1, _ := f.currentCert(t, "web-1st")
	layout1 := f.layout(t, "l1", "/etc/ssl/first.pem")
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.GrantInput{CertificateId: cert1, Delivery: push(), LayoutId: &layout1, HookIds: &[]uuid.UUID{h.Id}}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		certI, _ := f.currentCert(t, fmt.Sprintf("web-%d", i))
		layoutI := f.layout(t, fmt.Sprintf("l-%d", i), fmt.Sprintf("/etc/ssl/%d.pem", i))
		var wg sync.WaitGroup
		var updErr, createErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, updErr = f.srv.UpdateHook(op, gen.UpdateHookRequestObject{OrgId: f.org, Id: h.Id,
				Body: &gen.HookInput{Name: fmt.Sprintf("reload-%d", i), Phase: gen.HookPhase("post_deploy"), Argv: []string{"/bin/true"}, TimeoutSeconds: &sixty}})
		}()
		go func() {
			defer wg.Done()
			_, createErr = f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
				Body: &gen.GrantInput{CertificateId: certI, Delivery: push(), LayoutId: &layoutI, HookIds: &[]uuid.UUID{h.Id}}})
		}()
		wg.Wait()
		for _, err := range []error{updErr, createErr} {
			if err != nil && problemStatus(err) == 500 {
				t.Fatalf("iteration %d: got a 500 (deadlock): %v", i, err)
			}
		}
		if updErr != nil {
			t.Fatalf("iteration %d: unexpected hook update error: %v", i, updErr)
		}
		if createErr != nil {
			t.Fatalf("iteration %d: unexpected grant create error: %v", i, createErr)
		}
		var gid uuid.UUID
		if err := f.pool.QueryRow(ctx, `SELECT id FROM client_cert_grants WHERE client_id = $1 AND cert_id = $2`, c.ID, certI).Scan(&gid); err != nil {
			t.Fatal(err)
		}
		if _, err := f.srv.DeleteGrant(op, gen.DeleteGrantRequestObject{OrgId: f.org, Id: gid}); err != nil {
			t.Fatal(err)
		}
		_, _ = f.pool.Exec(ctx, `DELETE FROM client_cert_grants WHERE id = $1`, gid)
	}
}

// Fix round 2: same AB-BA shape as the hook case above, for a certificate
// rename. Before the fix, UpdateCertificate's rename locked the certificate
// (GetCertificateForUpdate, FOR UPDATE) then affected clients via
// ResyncCertificateRename/render, while CreateGrant locked the client first
// and the certificate second (LockCertificateForGrant, FOR KEY SHARE): a
// rename racing a CreateGrant for the same certificate, on a client that
// already holds a live grant on it, could deadlock. The client already has
// a live grant on this certificate, so the concurrent create always loses
// to the client/certificate uniqueness constraint (409); the rename always
// succeeds. The only unacceptable outcome is a 500.
func TestConcurrentCertificateRenameVsCreateGrantNoDeadlock(t *testing.T) {
	f := newAgentFixture(t)
	op, ctx := f.as("operator"), context.Background()
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		var wg sync.WaitGroup
		var renameErr, createErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, renameErr = f.srv.UpdateCertificate(op, gen.UpdateCertificateRequestObject{OrgId: f.org, Id: certID,
				Body: &gen.CertificateInput{Name: fmt.Sprintf("web-renamed-%d", i), CommonName: "web.example.test"}})
		}()
		go func() {
			defer wg.Done()
			_, createErr = f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
				Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}})
		}()
		wg.Wait()
		for _, err := range []error{renameErr, createErr} {
			if err != nil && problemStatus(err) == 500 {
				t.Fatalf("iteration %d: got a 500 (deadlock): %v", i, err)
			}
		}
		if renameErr != nil {
			t.Fatalf("iteration %d: unexpected rename error: %v", i, renameErr)
		}
		// The client already has a live grant on this certificate, so the
		// concurrent create always loses to the uniqueness constraint.
		if createErr == nil {
			t.Fatalf("iteration %d: duplicate grant create unexpectedly succeeded", i)
		}
		wantStatus(t, createErr, 409)
	}
	var name string
	_ = f.pool.QueryRow(ctx, `SELECT name FROM certificates WHERE id = $1`, certID).Scan(&name)
	if name != "web-renamed-7" {
		t.Fatalf("certificate not renamed by the last iteration: %s", name)
	}
}
