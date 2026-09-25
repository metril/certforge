//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/signer"
)

func push() gen.GrantDelivery { return gen.GrantDelivery("push") }

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
		PrivateKeyPKCS8: []byte("secret-key-2"), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Serial: "02"}, "ec256")
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
		PrivateKeyPKCS8: []byte("secret-key-3"), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Serial: "03"}, "ec256")
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
