package flow

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func id() uuid.UUID { return uuid.New() }

func tp(t time.Time) *time.Time { return &t }

func allPerms() Perms { return Perms{true, true, true, true, true, true} }

func hasEdge(g Graph, from, to string) (Edge, bool) {
	for _, e := range g.Edges {
		if e.From == from && e.To == to {
			return e, true
		}
	}
	return Edge{}, false
}

func TestCertStatus(t *testing.T) {
	cases := []struct {
		name string
		c    Cert
		want Status
	}{
		{"pending", Cert{Status: "pending"}, StatusPending},
		{"failed", Cert{Status: "failed", LastError: "boom"}, StatusFailed},
		{"revoked", Cert{Status: "revoked"}, StatusFailed},
		{"expired status", Cert{Status: "expired"}, StatusExpired},
		{"active no version", Cert{Status: "active"}, StatusValid},
		{"active far", Cert{Status: "active", NotAfter: tp(now.Add(90 * 24 * time.Hour))}, StatusValid},
		{"active near", Cert{Status: "active", NotAfter: tp(now.Add(5 * 24 * time.Hour))}, StatusExpiring},
		{"active past", Cert{Status: "active", NotAfter: tp(now.Add(-time.Hour))}, StatusExpired},
	}
	for _, tc := range cases {
		if got, _ := CertStatus(tc.c, now); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestChannelCoversCerts(t *testing.T) {
	cases := []struct {
		name string
		c    Channel
		want bool
	}{
		{"all kinds", Channel{Enabled: true, MinSeverity: "info"}, true},
		{"disabled", Channel{Enabled: false}, false},
		{"cert kind", Channel{Enabled: true, Events: []string{"cert.expired"}, MinSeverity: "critical"}, true},
		{"non-cert kinds only", Channel{Enabled: true, Events: []string{"backup.failed", "deploy.failed"}, MinSeverity: "info"}, false},
		{"severity too high for listed kind", Channel{Enabled: true, Events: []string{"cert.issued"}, MinSeverity: "warning"}, false},
		{"critical min, empty kinds", Channel{Enabled: true, MinSeverity: "critical"}, true},
	}
	for _, tc := range cases {
		if got := ChannelCoversCerts(tc.c); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAssembleEdgesAndStatus(t *testing.T) {
	ca, acct, dns := id(), id(), id()
	cert, layout, target, hook, client := id(), id(), id(), id(), id()
	ch, offCh := id(), id()
	in := Input{
		OrgSlug:  "acme",
		CAs:      []Item{{ID: ca, Name: "CA", Detail: "localca"}},
		Accounts: []Item{{ID: acct, Name: "a@x"}},
		DNSCreds: []Item{{ID: dns, Name: "cf"}},
		Certs:    []Cert{{ID: cert, Name: "web", Status: "active", CAID: &ca, AccountID: &acct, DNSCredIDs: []uuid.UUID{dns}}},
		Layouts:  []Item{{ID: layout, Name: "pem"}},
		Targets:  []Item{{ID: target, Name: "srv"}},
		Hooks:    []Item{{ID: hook, Name: "reload"}},
		Clients:  []Client{{ID: client, Name: "host", Status: "active"}},
		Grants: []Grant{
			{CertID: cert, ClientID: &client, LayoutID: &layout, HookIDs: []uuid.UUID{hook}, State: "drift"},
			{CertID: cert, TargetID: &target, State: "failed", Error: "nope"}, // server-run: no client
		},
		Channels: []Channel{
			{ID: ch, Name: "ops", Enabled: true, MinSeverity: "info", LastStatus: "failed", LastError: "500"},
			{ID: offCh, Name: "off", Enabled: false},
		},
	}
	g := Assemble(in, allPerms(), now)
	cn := "certificate:" + cert.String()
	for _, to := range []string{"ca:" + ca.String(), "account:" + acct.String(), "dnsCredential:" + dns.String(), "layout:" + layout.String(), "hook:" + hook.String(), "target:" + target.String()} {
		if _, ok := hasEdge(g, cn, to); !ok {
			t.Errorf("missing edge cert -> %s", to)
		}
	}
	if e, ok := hasEdge(g, "layout:"+layout.String(), "client:"+client.String()); !ok || e.Status != StatusDrift || e.Inferred {
		t.Errorf("layout->client = %+v ok=%v", e, ok)
	}
	if _, ok := hasEdge(g, "target:"+target.String(), "client:"+client.String()); ok {
		t.Error("server-run target must have no client edge")
	}
	if e, ok := hasEdge(g, cn, "target:"+target.String()); !ok || e.Status != StatusFailed {
		t.Errorf("cert->target = %+v", e)
	}
	// Inferred alert edge only for the enabled channel.
	if e, ok := hasEdge(g, cn, "channel:"+ch.String()); !ok || !e.Inferred {
		t.Errorf("cert->channel = %+v ok=%v, want inferred", e, ok)
	}
	if _, ok := hasEdge(g, cn, "channel:"+offCh.String()); ok {
		t.Error("disabled channel got an edge")
	}
	// Node statuses.
	byID := map[string]Node{}
	for _, l := range []Lane{g.Issuers, g.Certificates, g.Delivery, g.Clients, g.Alerts} {
		for _, n := range l.Nodes {
			byID[n.ID] = n
		}
	}
	if n := byID["target:"+target.String()]; n.Status != StatusFailed || n.StatusDetail != "nope" {
		t.Errorf("target node = %+v", n)
	}
	if n := byID["layout:"+layout.String()]; n.Status != StatusDrift {
		t.Errorf("layout node = %+v", n)
	}
	if n := byID["channel:"+ch.String()]; n.Status != StatusFailed || n.StatusDetail != "500" {
		t.Errorf("channel node = %+v", n)
	}
	if n := byID["channel:"+offCh.String()]; n.Status != StatusIdle || n.StatusDetail != "disabled" {
		t.Errorf("disabled channel node = %+v", n)
	}
	if n := byID[cn]; n.Href != "/o/acme/certificates/"+cert.String() {
		t.Errorf("cert href = %q", n.Href)
	}
	if n := byID["ca:"+ca.String()]; n.Href != "/o/acme/issuers/cas?view="+ca.String() {
		t.Errorf("ca href = %q", n.Href)
	}
}

func TestAssembleHiddenLanesDropEdges(t *testing.T) {
	ca, cert, layout, client, ch := id(), id(), id(), id(), id()
	in := Input{
		OrgSlug:  "acme",
		CAs:      []Item{{ID: ca, Name: "CA", Detail: "acme"}},
		Certs:    []Cert{{ID: cert, Name: "web", Status: "active", CAID: &ca}},
		Layouts:  []Item{{ID: layout, Name: "pem"}},
		Clients:  []Client{{ID: client, Name: "host", Status: "active"}},
		Grants:   []Grant{{CertID: cert, ClientID: &client, LayoutID: &layout, State: "ok"}},
		Channels: []Channel{{ID: ch, Name: "ops", Enabled: true}},
	}
	g := Assemble(in, Perms{}, now)
	if !g.Issuers.Hidden || !g.Delivery.Hidden || !g.Clients.Hidden || !g.Alerts.Hidden || g.Certificates.Hidden {
		t.Fatalf("hidden flags wrong: %+v", g)
	}
	if len(g.Issuers.Nodes)+len(g.Delivery.Nodes)+len(g.Clients.Nodes)+len(g.Alerts.Nodes) != 0 {
		t.Fatal("hidden lanes carry nodes")
	}
	if len(g.Edges) != 0 {
		t.Fatalf("edges touching hidden lanes survived: %+v", g.Edges)
	}
	// Delivery visible, clients hidden: cert->layout stays, layout->client goes.
	g = Assemble(in, Perms{Delivery: true}, now)
	if _, ok := hasEdge(g, "certificate:"+cert.String(), "layout:"+layout.String()); !ok {
		t.Error("cert->layout dropped")
	}
	if _, ok := hasEdge(g, "layout:"+layout.String(), "client:"+client.String()); ok {
		t.Error("layout->client kept with clients hidden")
	}
	// Issuers lane is visible when any one of its permissions is held.
	g = Assemble(in, Perms{Accounts: true}, now)
	if g.Issuers.Hidden {
		t.Error("issuers hidden despite accounts permission")
	}
	if len(g.Issuers.Nodes) != 0 {
		t.Error("CA node shown without cas:read")
	}
}

func TestAssembleTruncation(t *testing.T) {
	var certs []Cert
	for i := 0; i < 600; i++ {
		certs = append(certs, Cert{ID: id(), Name: fmt.Sprintf("c%03d", i), Status: "active"})
	}
	var clients []Client
	for i := 0; i < 300; i++ {
		clients = append(clients, Client{ID: id(), Name: fmt.Sprintf("h%03d", i), Status: "active"})
	}
	g := Assemble(Input{OrgSlug: "a", Certs: certs, Clients: clients}, allPerms(), now)
	total := len(g.Certificates.Nodes) + len(g.Clients.Nodes)
	if total != MaxNodes || !g.Truncated {
		t.Fatalf("total=%d truncated=%v", total, g.Truncated)
	}
	if len(g.Clients.Nodes) != maxSideNodes {
		t.Fatalf("clients = %d, want side cap %d", len(g.Clients.Nodes), maxSideNodes)
	}
	// Under the cap: not truncated.
	g = Assemble(Input{OrgSlug: "a", Certs: certs[:10]}, allPerms(), now)
	if g.Truncated {
		t.Fatal("small map truncated")
	}
	// The certificate list itself being cut short counts.
	g = Assemble(Input{OrgSlug: "a", Certs: certs[:10], CertsMore: true}, allPerms(), now)
	if !g.Truncated {
		t.Fatal("CertsMore did not set truncated")
	}
}

func TestAssembleEdgeCapDropsInferredFirst(t *testing.T) {
	var certs []Cert
	for i := 0; i < 400; i++ {
		certs = append(certs, Cert{ID: id(), Name: fmt.Sprintf("c%03d", i), Status: "active"})
	}
	var chans []Channel
	for i := 0; i < 20; i++ {
		chans = append(chans, Channel{ID: id(), Name: fmt.Sprintf("ch%02d", i), Enabled: true})
	}
	ca := id()
	for i := range certs {
		certs[i].CAID = &ca
	}
	g := Assemble(Input{OrgSlug: "a", Certs: certs, Channels: chans, CAs: []Item{{ID: ca, Name: "ca"}}}, allPerms(), now)
	if len(g.Edges) != MaxEdges || !g.Truncated {
		t.Fatalf("edges=%d truncated=%v", len(g.Edges), g.Truncated)
	}
	for _, e := range g.Edges[:400] {
		if e.Inferred {
			t.Fatal("a recorded edge was dropped in favour of an inferred one")
		}
	}
}
