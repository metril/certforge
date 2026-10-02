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
	if e, ok := hasEdge(g, "layout:"+layout.String(), "client:"+client.String()); !ok || e.Status != StatusDrift || e.CertID != cert.String() {
		t.Errorf("layout->client = %+v ok=%v", e, ok)
	}
	if _, ok := hasEdge(g, "target:"+target.String(), "client:"+client.String()); ok {
		t.Error("server-run target must have no client edge")
	}
	if e, ok := hasEdge(g, cn, "target:"+target.String()); !ok || e.Status != StatusFailed {
		t.Errorf("cert->target = %+v", e)
	}
	for _, e := range g.Edges {
		if e.To == "channel:"+ch.String() || e.From == "channel:"+ch.String() {
			t.Errorf("channel must have no edges, got %+v", e)
		}
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
	if n := byID["channel:"+ch.String()]; n.Status != StatusFailed || n.StatusDetail != "Last delivery failed: 500" {
		t.Errorf("channel node = %+v", n)
	}
	if !byID["channel:"+ch.String()].CoversCertificates || byID["channel:"+offCh.String()].CoversCertificates {
		t.Error("coversCertificates wrong")
	}
	if n := byID["channel:"+offCh.String()]; n.Status != StatusIdle || n.StatusDetail != "Disabled" {
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

func TestAssembleEdgeCap(t *testing.T) {
	var dns []Item
	var ids []uuid.UUID
	for i := 0; i < 12; i++ {
		d := id()
		ids = append(ids, d)
		dns = append(dns, Item{ID: d, Name: fmt.Sprintf("d%02d", i)})
	}
	var certs []Cert
	for i := 0; i < 450; i++ {
		certs = append(certs, Cert{ID: id(), Name: fmt.Sprintf("c%03d", i), Status: "active", DNSCredIDs: ids})
	}
	g := Assemble(Input{OrgSlug: "a", Certs: certs, DNSCreds: dns}, allPerms(), now)
	if len(g.Edges) != MaxEdges || !g.Truncated {
		t.Fatalf("edges=%d truncated=%v", len(g.Edges), g.Truncated)
	}
}

// Delivery-to-client edges are per certificate, and a hidden delivery lane
// still links the certificate to its visible client.
func TestAssembleSharedLayoutAndHiddenDelivery(t *testing.T) {
	certA, certB, layout, cA, cB := id(), id(), id(), id(), id()
	in := Input{OrgSlug: "a",
		Certs:   []Cert{{ID: certA, Name: "a", Status: "active"}, {ID: certB, Name: "b", Status: "active"}},
		Layouts: []Item{{ID: layout, Name: "pem"}},
		Clients: []Client{{ID: cA, Name: "ha", Status: "active"}, {ID: cB, Name: "hb", Status: "active"}},
		Grants: []Grant{
			{CertID: certA, ClientID: &cA, LayoutID: &layout, State: "ok"},
			{CertID: certB, ClientID: &cB, LayoutID: &layout, State: "ok"},
		}}
	g := Assemble(in, allPerms(), now)
	var toClient []Edge
	for _, e := range g.Edges {
		if e.From == "layout:"+layout.String() {
			toClient = append(toClient, e)
		}
	}
	if len(toClient) != 2 {
		t.Fatalf("layout->client edges = %+v", toClient)
	}
	for _, e := range toClient {
		want := certA.String()
		if e.To == "client:"+cB.String() {
			want = certB.String()
		}
		if e.CertID != want {
			t.Errorf("edge %+v has wrong certificate", e)
		}
	}
	g = Assemble(in, Perms{Clients: true}, now)
	if _, ok := hasEdge(g, "certificate:"+certA.String(), "client:"+cA.String()); !ok {
		t.Errorf("no direct cert->client edge with delivery hidden: %+v", g.Edges)
	}
}

func TestIssuerAndChannelStatuses(t *testing.T) {
	caUsed, caIdle, caSoon, caGone, acctOK, acctBad, dnsUsed, dnsIdle := id(), id(), id(), id(), id(), id(), id(), id()
	chNew, chOK, chPend := id(), id(), id()
	soon, gone, later := now.Add(3*24*time.Hour), now.Add(-time.Hour), now.Add(90*24*time.Hour)
	in := Input{
		OrgSlug: "acme",
		CAs: []Item{{ID: caUsed, Name: "u", Detail: "localca", NotAfter: &later}, {ID: caIdle, Name: "i", Detail: "acme"},
			{ID: caSoon, Name: "s", Detail: "localca", NotAfter: &soon}, {ID: caGone, Name: "g", Detail: "localca", NotAfter: &gone}},
		Accounts: []Item{{ID: acctOK, Name: "ok", Health: "valid"}, {ID: acctBad, Name: "bad", Health: "deactivated"}},
		DNSCreds: []Item{{ID: dnsUsed, Name: "du"}, {ID: dnsIdle, Name: "di"}},
		Certs: []Cert{
			{ID: id(), Name: "a", Status: "active", CAID: &caUsed, AccountID: &acctOK, DNSCredIDs: []uuid.UUID{dnsUsed}},
			{ID: id(), Name: "b", Status: "active", CAID: &caUsed},
		},
		Channels: []Channel{{ID: chNew, Name: "n", Enabled: true}, {ID: chOK, Name: "o", Enabled: true, LastStatus: "delivered", LastAt: &gone}, {ID: chPend, Name: "p", Enabled: true, LastStatus: "pending"}},
	}
	g := Assemble(in, allPerms(), now)
	byID := map[string]Node{}
	for _, l := range []Lane{g.Issuers, g.Alerts} {
		for _, n := range l.Nodes {
			byID[n.ID] = n
		}
	}
	chk := func(key string, st Status, d string) {
		t.Helper()
		if n := byID[key]; n.Status != st || n.StatusDetail != d {
			t.Errorf("%s = %s %q, want %s %q", key, n.Status, n.StatusDetail, st, d)
		}
	}
	chk("ca:"+caUsed.String(), StatusValid, "Used by 2 certificates")
	chk("ca:"+caIdle.String(), StatusIdle, "Not used by any certificate")
	chk("ca:"+caSoon.String(), StatusExpiring, "CA certificate expires in 3 days")
	chk("ca:"+caGone.String(), StatusExpired, "CA certificate expired")
	chk("account:"+acctOK.String(), StatusValid, "Used by 1 certificate")
	chk("account:"+acctBad.String(), StatusFailed, "Registration status: deactivated")
	chk("dnsCredential:"+dnsUsed.String(), StatusValid, "Used by 1 certificate")
	chk("dnsCredential:"+dnsIdle.String(), StatusIdle, "Not used by any certificate")
	chk("channel:"+chNew.String(), StatusIdle, "No deliveries yet")
	chk("channel:"+chPend.String(), StatusPending, "Delivery pending")
	chk("channel:"+chOK.String(), StatusValid, "Last delivered "+gone.UTC().Format("2006-01-02 15:04 UTC"))
}

// Issuer use is counted over every certificate handed in, so an issuer whose
// only user sits past the node cap is still in use; when the list itself is
// incomplete, counts are lower bounds and zero is never reported as unused.
func TestIssuerUsageBeyondCap(t *testing.T) {
	caLate, caNone := id(), id()
	var certs []Cert
	for i := 0; i < 600; i++ {
		c := Cert{ID: id(), Name: fmt.Sprintf("c%03d", i), Status: "active"}
		if i == 599 {
			c.CAID = &caLate
		}
		certs = append(certs, c)
	}
	in := Input{OrgSlug: "a", CAs: []Item{{ID: caLate, Name: "late", Detail: "acme"}, {ID: caNone, Name: "none", Detail: "acme"}}, Certs: certs}
	g := Assemble(in, allPerms(), now)
	if !g.Truncated {
		t.Fatal("not truncated")
	}
	got := map[string]Node{}
	for _, n := range g.Issuers.Nodes {
		got[n.ID] = n
	}
	if n := got["ca:"+caLate.String()]; n.Status != StatusValid || n.StatusDetail != "Used by 1 certificate" {
		t.Errorf("late CA = %s %q", n.Status, n.StatusDetail)
	}
	if n := got["ca:"+caNone.String()]; n.Status != StatusIdle || n.StatusDetail != "Not used by any certificate" {
		t.Errorf("unused CA = %s %q", n.Status, n.StatusDetail)
	}
	// Truncated list: lower bound, and zero is "not counted".
	in.Certs, in.UsageMore, in.CertsMore = certs[:10], true, true
	in.Certs[0].CAID = &caLate
	in.Certs[1].CAID = &caLate
	g = Assemble(in, allPerms(), now)
	got = map[string]Node{}
	for _, n := range g.Issuers.Nodes {
		got[n.ID] = n
	}
	if n := got["ca:"+caLate.String()]; n.Status != StatusValid || n.StatusDetail != "Used by at least 2 certificates" {
		t.Errorf("late CA = %s %q", n.Status, n.StatusDetail)
	}
	if n := got["ca:"+caNone.String()]; n.Status != StatusIdle || n.StatusDetail != UsageNotCounted {
		t.Errorf("zero-count CA = %s %q", n.Status, n.StatusDetail)
	}
}
