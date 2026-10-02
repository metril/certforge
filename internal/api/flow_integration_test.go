//go:build integration

package api

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

func flowLaneIDs(l gen.FlowLane) map[string]gen.FlowNode {
	m := map[string]gen.FlowNode{}
	for _, n := range l.Nodes {
		m[n.Id] = n
	}
	return m
}

func TestGetFlow(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	ctx := context.Background()

	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	if _, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}}); err != nil {
		t.Fatal(err)
	}
	ch, err := f.q.CreateNotificationChannel(ctx, sqlcgen.CreateNotificationChannelParams{OrgID: f.org, Name: "ops", Type: "webhook",
		Config: []byte(`{}`), Events: []string{}, MinSeverity: "info", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	res, err := f.srv.GetFlow(op, gen.GetFlowRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	fl := gen.Flow(res.(gen.GetFlow200JSONResponse))
	if fl.Truncated || fl.Lanes.Issuers.Hidden || fl.Lanes.Delivery.Hidden || fl.Lanes.Clients.Hidden || fl.Lanes.Alerts.Hidden {
		t.Fatalf("unexpected hidden/truncated: %+v", fl)
	}
	certNode := "certificate:" + certID.String()
	if n, ok := flowLaneIDs(fl.Lanes.Certificates)[certNode]; !ok || n.Status != gen.FlowStatus("expiring") {
		t.Fatalf("certificate node = %+v ok=%v", n, ok)
	}
	if _, ok := flowLaneIDs(fl.Lanes.Clients)["client:"+c.ID.String()]; !ok {
		t.Fatal("client node missing")
	}
	var toLayout, toClient bool
	for _, e := range fl.Edges {
		switch {
		case e.From == certNode && e.To == "layout:"+layout.String() && e.CertificateId == nil:
			toLayout = true
		case e.From == "layout:"+layout.String() && e.To == "client:"+c.ID.String() && e.CertificateId != nil && *e.CertificateId == certID:
			toClient = true
		case e.To == "channel:"+ch.ID.String() || e.From == "channel:"+ch.ID.String():
			t.Errorf("channel has an edge: %+v", e)
		}
	}
	if !toLayout || !toClient {
		t.Fatalf("edges: cert->layout=%v layout->client=%v in %+v", toLayout, toClient, fl.Edges)
	}
	if n := flowLaneIDs(fl.Lanes.Alerts)["channel:"+ch.ID.String()]; n.CoversCertificates == nil || !*n.CoversCertificates {
		t.Fatalf("channel node = %+v, want coversCertificates", n)
	}
}

// A key with only certs:read sees certificates (and issuers, which that scope
// covers); delivery, clients and alerts are hidden and no edge touches them.
func TestGetFlowHiddenLanes(t *testing.T) {
	f := newAgentFixture(t)
	c := f.activeClient(t, "web-1")
	certID, _ := f.currentCert(t, "web")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	if _, err := f.srv.CreateGrant(f.as("operator"), gen.CreateGrantRequestObject{OrgId: f.org, Id: c.ID,
		Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout}}); err != nil {
		t.Fatal(err)
	}
	res, err := f.srv.GetFlow(apiKeyPrincipal(f.org, []string{"certs:read"}), gen.GetFlowRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	fl := gen.Flow(res.(gen.GetFlow200JSONResponse))
	if fl.Lanes.Certificates.Hidden || len(fl.Lanes.Certificates.Nodes) != 1 {
		t.Fatalf("certificates lane = %+v", fl.Lanes.Certificates)
	}
	for name, l := range map[string]gen.FlowLane{"delivery": fl.Lanes.Delivery, "clients": fl.Lanes.Clients, "alerts": fl.Lanes.Alerts} {
		if !l.Hidden || len(l.Nodes) != 0 {
			t.Errorf("%s lane = %+v, want hidden and empty", name, l)
		}
	}
	// The certs:read scope also carries cas/accounts/dnscreds:read, so the issuers lane stays visible.
	if fl.Lanes.Issuers.Hidden {
		t.Error("issuers lane hidden despite cas/accounts/dnscreds read")
	}
	if len(fl.Edges) != 0 {
		t.Fatalf("edges survived hidden lanes: %+v", fl.Edges)
	}

	// Without certs:read at all: 403.
	_, err = f.srv.GetFlow(apiKeyPrincipal(f.org, []string{"alerts:read"}), gen.GetFlowRequestObject{OrgId: f.org})
	wantStatus(t, err, 403)
}

func TestGetFlowTruncates(t *testing.T) {
	f := newAgentFixture(t)
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO certificates (org_id, name, common_name, status) SELECT $1, 'c' || lpad(g::text, 4, '0'), 'c.example.test', 'pending' FROM generate_series(1, 520) g`, f.org); err != nil {
		t.Fatal(err)
	}
	res, err := f.srv.GetFlow(f.as("operator"), gen.GetFlowRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	fl := gen.Flow(res.(gen.GetFlow200JSONResponse))
	if !fl.Truncated || len(fl.Lanes.Certificates.Nodes) != 500 {
		t.Fatalf("truncated=%v certs=%d", fl.Truncated, len(fl.Lanes.Certificates.Nodes))
	}
}

// Another org's id is refused exactly as every other org-scoped endpoint
// refuses it (no binding there: 403, no leak of whether it exists).
func TestGetFlowOtherOrgRefused(t *testing.T) {
	f := newAgentFixture(t)
	other := dbtest.Org(t, f.pool)
	_, err := f.srv.GetFlow(f.as("operator"), gen.GetFlowRequestObject{OrgId: other})
	wantStatus(t, err, 403)
	_, err = f.srv.ListChannels(f.as("operator"), gen.ListChannelsRequestObject{OrgId: other})
	wantStatus(t, err, 403) // the same refusal other endpoints give
	_, err = f.srv.GetFlow(f.as("operator"), gen.GetFlowRequestObject{OrgId: uuid.New()})
	wantStatus(t, err, 403)
}
