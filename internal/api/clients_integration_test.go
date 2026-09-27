//go:build integration

package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/dbtest"
)

func TestCreateClientReturnsToken(t *testing.T) {
	f := newAgentFixture(t)
	res, err := f.srv.CreateClient(f.as("operator"), gen.CreateClientRequestObject{OrgId: f.org, Body: &gen.ClientInput{Name: " web-1 "}})
	if err != nil {
		t.Fatal(err)
	}
	out := res.(gen.CreateClient201JSONResponse)
	tok, err := agentproto.ParseToken(out.Token)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := f.ca.Active(context.Background())
	if tok.AgentURL != "https://cf.example.test:8443" || out.AgentUrl != tok.AgentURL || tok.CAFingerprint != agentca.Fingerprint(ca.Cert.Raw) {
		t.Fatalf("token %+v", tok)
	}
	if out.Client.Name != "web-1" || string(out.Client.Status) != "pending" || out.Client.TokenExpiresAt == nil || out.Client.Connected {
		t.Fatalf("client %+v", out.Client)
	}
	var stored int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM enrollment_tokens WHERE token_hash = $1`, agentproto.TokenHash(out.Token)).Scan(&stored)
	if stored != 1 || f.auditCount(t, "client.create") != 1 {
		t.Fatalf("stored %d audit %d", stored, f.auditCount(t, "client.create"))
	}
}

func TestClientOnlineFromLastSeen(t *testing.T) {
	f := newAgentFixture(t)
	pull := f.activeClient(t, "pull")
	f.activeClient(t, "stale")
	sock := f.activeClient(t, "sock")
	if _, err := f.pool.Exec(context.Background(), `UPDATE clients SET last_seen = CASE name WHEN 'pull' THEN now() - interval '30 seconds'
		ELSE now() - interval '1 hour' END WHERE org_id = $1`, f.org); err != nil {
		t.Fatal(err)
	}
	f.hub.mu.Lock()
	f.hub.online[sock.ID] = true
	f.hub.mu.Unlock()
	res, err := f.srv.ListClients(f.as("viewer"), gen.ListClientsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][2]bool{}
	for _, c := range res.(gen.ListClients200JSONResponse).Items {
		got[c.Name] = [2]bool{c.Online, c.Connected}
	}
	// offlineAfterSeconds defaults to 180: seen 30 s ago is online without a socket.
	for name, want := range map[string][2]bool{"pull": {true, false}, "stale": {false, false}, "sock": {true, true}} {
		if got[name] != want {
			t.Fatalf("%s online/connected %v, want %v", name, got[name], want)
		}
	}
	one, err := f.srv.GetClient(f.as("viewer"), gen.GetClientRequestObject{OrgId: f.org, Id: pull.ID})
	if err != nil || !one.(gen.GetClient200JSONResponse).Online || one.(gen.GetClient200JSONResponse).Connected {
		t.Fatalf("get %v %v", one, err)
	}
}

func TestClientNameUniqueAndSiteInOrg(t *testing.T) {
	f := newAgentFixture(t)
	f.newClient(t, "web-1")
	_, err := f.srv.CreateClient(f.as("operator"), gen.CreateClientRequestObject{OrgId: f.org, Body: &gen.ClientInput{Name: "web-1"}})
	wantStatus(t, err, 409)
	other := dbtest.Org(t, f.pool)
	var site uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO sites (org_id, name) VALUES ($1, 's') RETURNING id`, other).Scan(&site); err != nil {
		t.Fatal(err)
	}
	_, err = f.srv.CreateClient(f.as("operator"), gen.CreateClientRequestObject{OrgId: f.org, Body: &gen.ClientInput{Name: "web-2", SiteId: &site}})
	wantStatus(t, err, 422)
	_, err = f.srv.CreateClient(f.as("viewer"), gen.CreateClientRequestObject{OrgId: f.org, Body: &gen.ClientInput{Name: "web-3"}})
	wantStatus(t, err, 403)
}

func TestListClientsFiltersAndPaging(t *testing.T) {
	f := newAgentFixture(t)
	ctx := f.as("viewer")
	var site uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO sites (org_id, name) VALUES ($1, 'lab') RETURNING id`, f.org).Scan(&site); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alpha", "bravo", "charlie"} {
		f.newClient(t, n)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE clients SET site_id = $1 WHERE name = 'bravo'`, site); err != nil {
		t.Fatal(err)
	}
	list := func(p gen.ListClientsParams) gen.ClientList {
		t.Helper()
		res, err := f.srv.ListClients(ctx, gen.ListClientsRequestObject{OrgId: f.org, Params: p})
		if err != nil {
			t.Fatal(err)
		}
		return gen.ClientList(res.(gen.ListClients200JSONResponse))
	}
	names := func(l gen.ClientList) string {
		var s []string
		for _, c := range l.Items {
			s = append(s, c.Name)
		}
		return strings.Join(s, ",")
	}
	two := 2
	page := list(gen.ListClientsParams{Limit: &two})
	if names(page) != "alpha,bravo" || page.NextCursor == nil {
		t.Fatalf("page 1 %s", names(page))
	}
	if next := list(gen.ListClientsParams{Limit: &two, Cursor: page.NextCursor}); names(next) != "charlie" || next.NextCursor != nil {
		t.Fatalf("page 2 %s", names(next))
	}
	desc := "-name"
	if got := names(list(gen.ListClientsParams{Sort: &desc})); got != "charlie,bravo,alpha" {
		t.Fatalf("desc %s", got)
	}
	if got := names(list(gen.ListClientsParams{Site: &site})); got != "bravo" {
		t.Fatalf("site %s", got)
	}
	q := "ARL"
	if got := names(list(gen.ListClientsParams{Q: &q})); got != "charlie" {
		t.Fatalf("q %s", got)
	}
	st := gen.ClientStatus("active")
	if got := names(list(gen.ListClientsParams{Status: &st})); got != "" {
		t.Fatalf("status %s", got)
	}
	_, err := f.srv.ListClients(ctx, gen.ListClientsRequestObject{OrgId: f.org, Params: gen.ListClientsParams{Sort: &desc, Cursor: page.NextCursor}})
	wantStatus(t, err, 422)
	bad := "created"
	_, err = f.srv.ListClients(ctx, gen.ListClientsRequestObject{OrgId: f.org, Params: gen.ListClientsParams{Sort: &bad}})
	wantStatus(t, err, 422)
}

func TestListAllClientsNeedsReadableOrg(t *testing.T) {
	f := newAgentFixture(t)
	f.newClient(t, "web-1")
	res, err := f.srv.ListAllClients(f.as("viewer"), gen.ListAllClientsRequestObject{})
	if err != nil || len(res.(gen.ListAllClients200JSONResponse).Items) != 1 {
		t.Fatalf("all %v %v", res, err)
	}
	none := authn.WithPrincipal(context.Background(), authn.Principal{Kind: authn.KindUser, UserID: uuid.New()})
	_, err = f.srv.ListAllClients(none, gen.ListAllClientsRequestObject{})
	wantStatus(t, err, 403)
}

// TestDeleteClientReferencedByRule (Task 7): a client still named by a
// certificate's verification rule cannot be deleted until the rule is
// changed, the same protection DeleteDNSCredential and DeleteCA already
// have for their own referenced rows.
func TestDeleteClientReferencedByRule(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	en := f.newClient(t, "web-1") // pending: deletable but for the rule reference
	if _, err := f.pool.Exec(context.Background(), `UPDATE clients SET capabilities = '{tls-alpn-01}' WHERE id = $1`, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	res, err := f.srv.CreateCertificate(op, gen.CreateCertificateRequestObject{OrgId: f.org,
		Body: &gen.CertificateInput{Name: "web", CommonName: "web.example.test",
			VerificationRules: &[]gen.VerificationRule{{Match: "web.example.test", Method: "tls-alpn-01", ClientId: &en.Client.ID}}}})
	if err != nil {
		t.Fatal(err)
	}
	cert := res.(gen.CreateCertificate201JSONResponse)
	_, err = f.srv.DeleteClient(op, gen.DeleteClientRequestObject{OrgId: f.org, Id: en.Client.ID})
	wantStatus(t, err, 409)
	var he *HTTPError
	if !errors.As(err, &he) || !strings.Contains(he.Detail, cert.Name) {
		t.Fatalf("conflict does not name the certificate: %v", err)
	}
}

func TestRevokeReenrollDelete(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	c := f.activeClient(t, "web-1")
	f.hub.online[c.ID] = true
	_, err := f.srv.DeleteClient(op, gen.DeleteClientRequestObject{OrgId: f.org, Id: c.ID})
	wantStatus(t, err, 409)
	res, err := f.srv.ReenrollClient(op, gen.ReenrollClientRequestObject{OrgId: f.org, Id: c.ID})
	if err != nil {
		t.Fatal(err)
	}
	re := res.(gen.ReenrollClient200JSONResponse)
	if string(re.Client.Status) != "pending" || re.Token == "" || f.hub.closed[c.ID] != agentproto.CloseRevoked {
		t.Fatalf("reenroll %+v closed %d", re.Client, f.hub.closed[c.ID])
	}
	var tokens int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM enrollment_tokens WHERE client_id = $1 AND used_at IS NULL`, c.ID).Scan(&tokens)
	if tokens != 1 {
		t.Fatalf("unused tokens %d", tokens)
	}
	rv, err := f.srv.RevokeClient(op, gen.RevokeClientRequestObject{OrgId: f.org, Id: c.ID})
	if err != nil || string(rv.(gen.RevokeClient200JSONResponse).Status) != "revoked" {
		t.Fatalf("revoke %v %v", rv, err)
	}
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM enrollment_tokens WHERE client_id = $1 AND used_at IS NULL`, c.ID).Scan(&tokens)
	if tokens != 0 {
		t.Fatalf("tokens after revoke %d", tokens)
	}
	if _, err := f.srv.RevokeClient(op, gen.RevokeClientRequestObject{OrgId: f.org, Id: c.ID}); err != nil {
		t.Fatalf("second revoke %v", err)
	}
	_, err = f.srv.ReenrollClient(op, gen.ReenrollClientRequestObject{OrgId: f.org, Id: c.ID})
	wantStatus(t, err, 409)
	if _, err := f.srv.DeleteClient(op, gen.DeleteClientRequestObject{OrgId: f.org, Id: c.ID}); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"client.reenroll", "client.revoke", "client.delete"} {
		if f.auditCount(t, a) < 1 {
			t.Errorf("no %s audit", a)
		}
	}
	if f.auditCount(t, "client.revoke") != 1 {
		t.Fatal("second revoke was audited")
	}
}

// Review Focus (final fix wave, I3): a revoked client's agent can never
// come back to confirm a removal, so RevokeClient hard-deletes every grant
// of this client still awaiting one instead of leaving it removal-pending
// forever.
func TestRevokeClientHardDeletesRemovalPendingGrants(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	c := f.activeClient(t, "web-1")
	if _, err := f.pool.Exec(context.Background(), `UPDATE clients SET applied_revision = 1 WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.GrantInput{CertificateId: certID, Delivery: gen.GrantDelivery("push"), LayoutId: &layout}})
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
	if _, err := f.srv.RevokeClient(op, gen.RevokeClientRequestObject{OrgId: f.org, Id: c.ID}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM client_cert_grants WHERE id = $1`, gid).Scan(&n)
	if n != 0 {
		t.Fatal("revoke did not hard-delete the removal-pending grant")
	}
	var details string
	_ = f.pool.QueryRow(context.Background(), `SELECT details::text FROM audit_events WHERE action = 'grant.delete' AND resource_id = $1 ORDER BY id DESC LIMIT 1`, gid.String()).Scan(&details)
	if !strings.Contains(details, `"forced": true`) {
		t.Fatalf("forced not audited: %s", details)
	}
}

func TestUpdateClientAudit(t *testing.T) {
	f := newAgentFixture(t)
	c := f.newClient(t, "web-1").Client
	res, err := f.srv.UpdateClient(f.as("operator"), gen.UpdateClientRequestObject{OrgId: f.org, Id: c.ID, Body: &gen.ClientUpdate{Name: "web-one"}})
	if err != nil || res.(gen.UpdateClient200JSONResponse).Name != "web-one" {
		t.Fatalf("update %v %v", res, err)
	}
	var details string
	_ = f.pool.QueryRow(context.Background(), `SELECT details::text FROM audit_events WHERE action = 'client.update'`).Scan(&details)
	if !strings.Contains(details, `"before"`) || !strings.Contains(details, "web-one") {
		t.Fatalf("details %s", details)
	}
}

// Review carry-forward: a client in another org must 404, not leak through
// a 200 or 403, and GET /clients must silently drop orgs the caller cannot
// read rather than erroring or including them.
func TestClientCrossOrg404(t *testing.T) {
	f := newAgentFixture(t)
	org2 := dbtest.Org(t, f.pool)
	en, err := f.svc.CreateClient(context.Background(), org2, "other-org", nil)
	if err != nil {
		t.Fatal(err)
	}
	op := f.as("operator") // bound to f.org only, not org2
	if _, err := f.srv.GetClient(op, gen.GetClientRequestObject{OrgId: f.org, Id: en.Client.ID}); err == nil {
		t.Fatal("cross-org get succeeded")
	} else {
		wantStatus(t, err, 404)
	}
	if _, err := f.srv.UpdateClient(op, gen.UpdateClientRequestObject{OrgId: f.org, Id: en.Client.ID, Body: &gen.ClientUpdate{Name: "hijacked"}}); err == nil {
		t.Fatal("cross-org update succeeded")
	} else {
		wantStatus(t, err, 404)
	}
	if _, err := f.srv.RevokeClient(op, gen.RevokeClientRequestObject{OrgId: f.org, Id: en.Client.ID}); err == nil {
		t.Fatal("cross-org revoke succeeded")
	} else {
		wantStatus(t, err, 404)
	}
	if _, err := f.srv.ReenrollClient(op, gen.ReenrollClientRequestObject{OrgId: f.org, Id: en.Client.ID}); err == nil {
		t.Fatal("cross-org reenroll succeeded")
	} else {
		wantStatus(t, err, 404)
	}
	if _, err := f.srv.DeleteClient(op, gen.DeleteClientRequestObject{OrgId: f.org, Id: en.Client.ID}); err == nil {
		t.Fatal("cross-org delete succeeded")
	} else {
		wantStatus(t, err, 404)
	}
	// The client in org2 is untouched by any of the above.
	c, err := f.q.GetClientByID(context.Background(), en.Client.ID)
	if err != nil || c.Status != "pending" || c.Name != "other-org" {
		t.Fatalf("client mutated across orgs: %+v %v", c, err)
	}
}

// GET /clients (cross-org listing) hides orgs the caller cannot read instead
// of erroring or including them.
func TestListAllClientsHidesUnreadableOrgs(t *testing.T) {
	f := newAgentFixture(t)
	org2 := dbtest.Org(t, f.pool)
	f.newClient(t, "own-org")
	if _, err := f.svc.CreateClient(context.Background(), org2, "other-org", nil); err != nil {
		t.Fatal(err)
	}
	res, err := f.srv.ListAllClients(f.as("operator"), gen.ListAllClientsRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	items := res.(gen.ListAllClients200JSONResponse).Items
	if len(items) != 1 || items[0].Name != "own-org" {
		t.Fatalf("cross-org listing leaked: %+v", items)
	}
}

func TestOrgDeleteBlockedByClients(t *testing.T) {
	f := newAgentFixture(t)
	f.newClient(t, "web-1")
	_, err := f.srv.DeleteOrg(f.as("admin"), gen.DeleteOrgRequestObject{OrgId: f.org})
	wantStatus(t, err, 409)
	var he *HTTPError
	if !errors.As(err, &he) || !strings.Contains(he.Detail, "1 client") {
		t.Fatalf("err %v", err)
	}
}
