package challenge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// fakeUpstream answers every query with h and returns its host:port.
func fakeUpstream(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()
	return startSplitDNS(t, h, h)
}

// soaUpstream is authoritative for zone only: SOA at zone, NXDOMAIN with the
// zone's SOA in authority elsewhere under it is not needed by lego's lookup,
// so everything else is NODATA.
func soaUpstream(t *testing.T, zone string) string {
	return fakeUpstream(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeSOA && q.Name == zone {
			m.Authoritative = true
			m.Answer = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns: "ns." + zone, Mbox: "h." + zone, Minttl: 60}}
		}
		_ = w.WriteMsg(m)
	})
}

// startForwarder serves the forwarder handler on a private port; the real
// StartZoneForwarder also records its address in a package global.
func startForwarder(t *testing.T) string {
	t.Helper()
	return startSplitDNS(t, serveZoneQuery, serveZoneQuery)
}

func TestResolversForMatching(t *testing.T) {
	isolateZones(t)
	a := []string{"10.0.0.1:53"}
	b := []string{"10.0.0.2:53"}
	relA := RegisterZone([]string{"*.A.example.com", "a.example.com"}, a)
	defer relA()
	relB := RegisterZone([]string{"b.other.org"}, b)
	defer relB()
	cases := []struct {
		q    string
		want []string
	}{
		{"a.example.com.", a},
		{"_acme-challenge.a.example.com.", a},
		{"example.com.", a},
		{".", nil}, // parent of both lists: ambiguous
		{"b.other.org.", b},
		{"_acme-challenge.b.other.org.", b},
		{"other.org.", b},
		{"unrelated.net.", nil},
		{"sub.a.example.com.", nil}, // child, not parent
	}
	for _, c := range cases {
		if got := resolversFor(c.q); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v want %v", c.q, got, c.want)
		}
	}
	relB()
	if got := resolversFor("."); !slices.Equal(got, a) {
		t.Errorf("after release: got %v", got)
	}
	relA()
	if got := resolversFor("a.example.com."); got != nil {
		t.Errorf("after release: got %v", got)
	}
}

func TestSameListIsNotAmbiguous(t *testing.T) {
	isolateZones(t)
	a := []string{"10.1.0.1:53"}
	r1 := RegisterZone([]string{"x.same.test"}, a)
	r2 := RegisterZone([]string{"y.same.test"}, append([]string(nil), a...))
	defer r1()
	defer r2()
	if got := resolversFor("same.test."); !slices.Equal(got, a) {
		t.Errorf("got %v", got)
	}
}

func TestForwarderUsesRegisteredUpstream(t *testing.T) {
	isolateZones(t)
	up := soaUpstream(t, "e2e-zone.test.")
	fwd := startForwarder(t)
	rel := RegisterZone([]string{"*.e2e-zone.test", "e2e-zone.test"}, []string{up})
	defer rel()
	zone, err := dns01.FindZoneByFqdnCustom("_acme-challenge.e2e-zone.test.", []string{fwd})
	if err != nil || zone != "e2e-zone.test." {
		t.Fatalf("zone=%q err=%v", zone, err)
	}
}

func TestForwarderFallsBackToDefaultResolvers(t *testing.T) {
	isolateZones(t)
	up := soaUpstream(t, "fallback-zone.test.")
	fwd := startForwarder(t)
	old := SetDefaultResolvers(func() []string { return []string{up} })
	t.Cleanup(func() { SetDefaultResolvers(old) })
	zone, err := dns01.FindZoneByFqdnCustom("_acme-challenge.fallback-zone.test.", []string{fwd})
	if err != nil || zone != "fallback-zone.test." {
		t.Fatalf("zone=%q err=%v", zone, err)
	}
}

func TestForwarderTriesNextResolverThenServfail(t *testing.T) {
	isolateZones(t)
	up := soaUpstream(t, "next.test.")
	fwd := startForwarder(t)
	rel := RegisterZone([]string{"next.test"}, []string{"127.0.0.1:1", up})
	m := new(dns.Msg)
	m.SetQuestion("next.test.", dns.TypeSOA)
	in, _, err := exchange(context.Background(), fwd, m)
	if err != nil || len(in.Answer) != 1 || in.Id != m.Id {
		t.Fatalf("in=%v err=%v", in, err)
	}
	rel()
	rel = RegisterZone([]string{"next.test"}, []string{"127.0.0.1:1"})
	defer rel()
	in, _, err = exchange(context.Background(), fwd, m)
	if err != nil || in.Rcode != dns.RcodeServerFailure {
		t.Fatalf("in=%v err=%v", in, err)
	}
}

func TestForwarderPassesRcodeUnchanged(t *testing.T) {
	isolateZones(t)
	up := fakeUpstream(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
	})
	fwd := startForwarder(t)
	rel := RegisterZone([]string{"nx.test"}, []string{up})
	defer rel()
	m := new(dns.Msg)
	m.SetQuestion("nx.test.", dns.TypeA)
	in, _, err := exchange(context.Background(), fwd, m)
	if err != nil || in.Rcode != dns.RcodeNameError {
		t.Fatalf("in=%v err=%v", in, err)
	}
}

func TestForwarderDoH(t *testing.T) {
	isolateZones(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"doh"}}}
		wire, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer srv.Close()
	old := dohClient
	dohClient = srv.Client()
	t.Cleanup(func() { dohClient = old })
	fwd := startForwarder(t)
	rel := RegisterZone([]string{"doh-zone.test"}, []string{srv.URL})
	defer rel()
	m := new(dns.Msg)
	m.SetQuestion("doh-zone.test.", dns.TypeTXT)
	in, _, err := exchange(context.Background(), fwd, m)
	if err != nil || !hasTXT(in, "doh") || in.Id != m.Id {
		t.Fatalf("in=%v err=%v", in, err)
	}
}

func TestRouterRegistersAndCloses(t *testing.T) {
	isolateZones(t)
	res := []string{"10.9.0.1:53"}
	p := &recProvider{name: "p"}
	rules := []Rule{{Matcher: mustMatch(t, "*.router-reg.test"), Provider: p, Resolvers: res}}
	r := NewRouter(context.Background(), []string{"*.router-reg.test", "router-reg.test"}, rules, nil)
	if got := resolversFor("_acme-challenge.router-reg.test."); !slices.Equal(got, res) {
		t.Fatalf("got %v", got)
	}
	r.Close()
	r.Close()
	if got := resolversFor("router-reg.test."); got != nil {
		t.Fatalf("after Close: %v", got)
	}
}

func TestHintZone(t *testing.T) {
	isolateZones(t)
	r := NewRouter(context.Background(), nil, nil, nil)
	for _, msg := range []string{"cloudflare: failed to find zone x.: zone could not be found", "zone could not be found"} {
		if h := r.Hint(errString(msg)); h != hintZone {
			t.Errorf("%q: hint %q", msg, h)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func mustMatch(t *testing.T, s string) Matcher {
	t.Helper()
	m, err := ParseMatch(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// isolateZones gives the test an empty registry; other tests build Routers
// with resolvers and never Close them.
func isolateZones(t *testing.T) {
	t.Helper()
	zoneMu.Lock()
	old := zoneRegs
	zoneRegs = map[*zoneReg]struct{}{}
	zoneMu.Unlock()
	t.Cleanup(func() {
		zoneMu.Lock()
		zoneRegs = old
		zoneMu.Unlock()
	})
}
