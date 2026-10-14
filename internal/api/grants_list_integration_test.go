//go:build integration

package api

import (
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
)

func TestListGrantsFilters(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	ex := f.execAction(t, "e")
	wt := f.waitAction(t, "w")
	mkGroup := func(name string, id uuid.UUID) uuid.UUID {
		res, err := f.srv.CreateActionGroup(op, gen.CreateActionGroupRequestObject{OrgId: f.org, Body: &gen.ActionGroupInput{Name: name, ActionIds: []uuid.UUID{id}}})
		if err != nil {
			t.Fatal(err)
		}
		return res.(gen.CreateActionGroup201JSONResponse).Id
	}
	gx, gw := mkGroup("gx", ex.Id), mkGroup("gw", wt.Id)
	c1, c2 := f.activeClient(t, "web-1"), f.activeClient(t, "web-2")
	web, _ := f.currentCert(t, "web")
	api, _ := f.currentCert(t, "api")
	layout := f.layout(t, "pem", "/etc/ssl/web.pem")
	targetID, _ := f.serverTarget(t, "vault", nil)

	agent := func(clientID, certID uuid.UUID, steps []gen.GrantStep) uuid.UUID {
		res, err := f.srv.CreateGrant(op, gen.CreateGrantRequestObject{OrgId: f.org, Id: clientID,
			Body: &gen.GrantInput{CertificateId: certID, Delivery: push(), LayoutId: &layout, Steps: &steps}})
		if err != nil {
			t.Fatal(err)
		}
		return res.(gen.CreateGrant201JSONResponse).Id
	}
	g1 := agent(c1.ID, web, stepsOf(ex.Id))                 // action direct
	g2 := agent(c2.ID, api, []gen.GrantStep{groupStep(gx)}) // action via group
	steps := []gen.GrantStep{groupStep(gw)}
	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: web, Steps: &steps}})
	if err != nil {
		t.Fatal(err)
	}
	g3 := res.(gen.CreateServerGrant201JSONResponse).Id

	list := func(p gen.ListGrantsParams) []gen.Grant {
		t.Helper()
		r, err := f.srv.ListGrants(f.as("viewer"), gen.ListGrantsRequestObject{OrgId: f.org, Params: p})
		if err != nil {
			t.Fatal(err)
		}
		return r.(gen.ListGrants200JSONResponse).Items
	}
	ids := func(items []gen.Grant) map[uuid.UUID]bool {
		m := map[uuid.UUID]bool{}
		for _, g := range items {
			m[g.Id] = true
		}
		return m
	}
	check := func(name string, p gen.ListGrantsParams, want ...uuid.UUID) {
		t.Helper()
		items := list(p)
		got := ids(items)
		if len(items) != len(want) || len(got) != len(want) {
			t.Errorf("%s: got %d items, want %d", name, len(items), len(want))
			return
		}
		for _, id := range want {
			if !got[id] {
				t.Errorf("%s: missing %s", name, id)
			}
		}
	}
	check("none", gen.ListGrantsParams{}, g1, g2, g3)
	check("certificate", gen.ListGrantsParams{CertificateId: &web}, g1, g3)
	check("client", gen.ListGrantsParams{ClientId: &c1.ID}, g1)
	check("layout", gen.ListGrantsParams{LayoutId: &layout}, g1, g2)
	check("target", gen.ListGrantsParams{DeployTargetId: &targetID}, g3)
	check("action direct", gen.ListGrantsParams{ActionId: &ex.Id}, g1, g2)
	check("action via group", gen.ListGrantsParams{ActionId: &wt.Id}, g3)
	check("group", gen.ListGrantsParams{ActionGroupId: &gx}, g2)
	check("grant", gen.ListGrantsParams{GrantId: &g3}, g3)
	check("AND", gen.ListGrantsParams{CertificateId: &web, ActionId: &ex.Id}, g1)

	for _, g := range list(gen.ListGrantsParams{}) {
		switch g.Id {
		case g1:
			if g.LayoutName == nil || *g.LayoutName != "pem" || g.DeployTargetName != nil || g.ClientName == nil {
				t.Errorf("agent grant names: %+v", g)
			}
		case g3:
			if g.DeployTargetName == nil || *g.DeployTargetName != "vault" || g.LayoutName != nil || g.RunsOn != gen.RunsOnServer {
				t.Errorf("server grant names: %+v", g)
			}
		}
	}
}

func TestMonitorListGrantDeployTargetID(t *testing.T) {
	f := newAgentFixture(t)
	op := f.as("operator")
	targetID, _ := f.serverTarget(t, "vault", nil)
	certID, _ := f.currentCert(t, "web")
	res, err := f.srv.CreateServerGrant(op, gen.CreateServerGrantRequestObject{OrgId: f.org, Id: targetID,
		Body: &gen.ServerGrantInput{CertificateId: certID, Verify: &gen.GrantVerify{Host: "x.example.test", Port: 8443}}})
	if err != nil {
		t.Fatal(err)
	}
	g := res.(gen.CreateServerGrant201JSONResponse)
	lr, err := f.srv.ListMonitors(f.as("viewer"), gen.ListMonitorsRequestObject{OrgId: f.org})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, m := range lr.(gen.ListMonitors200JSONResponse) {
		if m.GrantId != nil && *m.GrantId == g.Id {
			found = true
			if m.GrantDeployTargetId == nil || *m.GrantDeployTargetId != targetID {
				t.Errorf("grantDeployTargetId = %v, want %s", m.GrantDeployTargetId, targetID)
			}
		}
	}
	if !found {
		t.Fatal("grant-owned monitor not listed")
	}
}
