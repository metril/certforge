package challenge

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type recProvider struct {
	name    string
	mu      sync.Mutex
	present []string
	timeout time.Duration
}

func (p *recProvider) Type() Type { return DNS01 }
func (p *recProvider) Present(_ context.Context, d, _, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.present = append(p.present, d)
	return nil
}
func (p *recProvider) CleanUp(context.Context, string, string, string) error { return nil }
func (p *recProvider) Timeout() (time.Duration, time.Duration)               { return p.timeout, time.Second }

func rule(t *testing.T, pattern string, p ChallengeProvider) Rule {
	t.Helper()
	m, err := ParseMatch(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return Rule{Matcher: m, Provider: p, Label: pattern}
}

// Review Focus: a name matching no rule and no catch-all fails before ordering.
func TestRouterValidateUncoveredName(t *testing.T) {
	a := &recProvider{name: "a"}
	r := NewRouter(context.Background(), []string{"example.com", "lab.local"}, []Rule{rule(t, "example.com", a)}, nil)
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "lab.local") || !strings.Contains(err.Error(), "no catch-all") {
		t.Fatalf("Validate() = %v", err)
	}
	if err := r.Present("lab.local", "tok", "ka"); err == nil {
		t.Fatal("Present on uncovered name must fail")
	}
	if len(a.present) != 0 {
		t.Fatal("provider must not be called for uncovered name")
	}
}

func TestRouterValidateRejectsIP(t *testing.T) {
	r := NewRouter(context.Background(), []string{"192.0.2.1"}, []Rule{rule(t, "*", &recProvider{})}, nil)
	if err := r.Validate(); err == nil {
		t.Fatal("want IP error")
	}
}

// Review Focus: two credentials for overlapping zones, first match in list order wins.
func TestRouterOverlappingZonesFirstMatchWins(t *testing.T) {
	broad, narrow := &recProvider{name: "broad"}, &recProvider{name: "narrow"}
	names := []string{"a.dev.example.com", "www.example.com"}

	r := NewRouter(context.Background(), names, []Rule{rule(t, "dev.example.com", narrow), rule(t, "example.com", broad)}, nil)
	for _, n := range names {
		if err := r.Present(n, "t", "k"); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(narrow.present, ",") != "a.dev.example.com" || strings.Join(broad.present, ",") != "www.example.com" {
		t.Fatalf("narrow-first: narrow=%v broad=%v", narrow.present, broad.present)
	}

	broad2, narrow2 := &recProvider{}, &recProvider{}
	r = NewRouter(context.Background(), names, []Rule{rule(t, "example.com", broad2), rule(t, "dev.example.com", narrow2)}, nil)
	for _, n := range names {
		_ = r.Present(n, "t", "k")
	}
	if len(narrow2.present) != 0 || len(broad2.present) != 2 {
		t.Fatalf("broad-first must shadow narrow: narrow=%v broad=%v", narrow2.present, broad2.present)
	}
}

func TestRouterWildcardAuthzUsesWildcardRule(t *testing.T) {
	wild, other := &recProvider{}, &recProvider{}
	r := NewRouter(context.Background(), []string{"*.example.com", "other.net"},
		[]Rule{rule(t, "*.example.com", wild), rule(t, "other.net", other)}, nil)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	// lego passes the bare domain for wildcard authorizations.
	if err := r.Present("example.com", "t", "k"); err != nil {
		t.Fatal(err)
	}
	if len(wild.present) != 1 {
		t.Fatal("wildcard authz not routed to *.example.com rule")
	}
}

// Review Focus: lego calls Present/CleanUp with the bare authorization
// domain for both the apex and wildcard authorizations of one certificate,
// but calls PreCheck with "*.example.com" for the wildcard one
// (challenge.GetTargetedDomain). When both names are configured, all three
// callbacks must resolve to the same rule for the wildcard authorization:
// whichever rule matches the bare domain "example.com" (the ADR's "the apex
// rule serves both"), not a rule that only matches "*.example.com" itself.
func TestRouterApexAndWildcardShareRule(t *testing.T) {
	apexProv := &recProvider{timeout: 30 * time.Second}
	wildProv := &recProvider{timeout: time.Hour}
	wild := rule(t, "*.example.com", wildProv)
	wild.AliasZone = "alias.example.net" // would break PreCheck if wrongly routed here
	apex := rule(t, "example.com", apexProv)
	apex.Timeout = 5 * time.Minute

	r := NewRouter(context.Background(), []string{"example.com", "*.example.com"}, []Rule{wild, apex}, nil)

	if err := r.Present("example.com", "t", "k"); err != nil {
		t.Fatal(err)
	}
	if len(apexProv.present) != 1 || len(wildProv.present) != 0 {
		t.Fatalf("Present must use the apex rule: apex=%v wild=%v", apexProv.present, wildProv.present)
	}

	ok, err := r.PreCheck("*.example.com", "_acme-challenge.example.com.", "v", func(string, string) (bool, error) { return true, nil })
	if !ok || err != nil {
		t.Fatalf("PreCheck for the wildcard authz must use the apex rule (no alias zone): %v %v", ok, err)
	}

	if got, _ := r.Timeout(); got != 5*time.Minute {
		t.Fatalf("Timeout = %v, want the apex rule's 5m, not the wildcard rule's 1h", got)
	}
}

func TestRouterTimeoutUsesLargestRuleInUse(t *testing.T) {
	a := &recProvider{timeout: 30 * time.Second}
	unused := &recProvider{timeout: time.Hour}
	ra := rule(t, "example.com", a)
	ra.Timeout = 5 * time.Minute
	r := NewRouter(context.Background(), []string{"example.com"}, []Rule{ra, rule(t, "other.net", unused)}, nil)
	if got, _ := r.Timeout(); got != 5*time.Minute {
		t.Fatalf("Timeout = %v", got)
	}
}

func TestRouterPreCheckAliasZone(t *testing.T) {
	ru := rule(t, "example.com", &recProvider{})
	ru.AliasZone = "acme.example.net"
	r := NewRouter(context.Background(), []string{"example.com"}, []Rule{ru}, nil)
	ok, err := r.PreCheck("example.com", "_acme-challenge.example.com.", "v", func(string, string) (bool, error) { return true, nil })
	if ok || err == nil || !strings.Contains(err.Error(), "alias zone") {
		t.Fatalf("PreCheck = %v, %v", ok, err)
	}
	ok, err = r.PreCheck("example.com", "example.com.acme.example.net.", "v", func(string, string) (bool, error) { return true, nil })
	if !ok || err != nil {
		t.Fatalf("PreCheck in alias zone = %v, %v", ok, err)
	}
}

// startDNS serves TXT answers from records on a random UDP port.
func startDNS(t *testing.T, records map[string]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		if v, ok := records[q.Name]; ok && q.Qtype == dns.TypeTXT {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{v}})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestRouterPreCheckUsesRuleResolvers(t *testing.T) {
	addr := startDNS(t, map[string]string{"_acme-challenge.example.com.": "good"})
	ru := rule(t, "example.com", &recProvider{})
	ru.Resolvers = []string{addr}
	r := NewRouter(context.Background(), []string{"example.com"}, []Rule{ru}, nil)
	legoCheck := func(string, string) (bool, error) { return false, errors.New("lego default check must not run") }

	ok, err := r.PreCheck("example.com", "_acme-challenge.example.com.", "good", legoCheck)
	if !ok || err != nil {
		t.Fatalf("propagated: %v %v", ok, err)
	}
	ok, err = r.PreCheck("example.com", "_acme-challenge.example.com.", "other", legoCheck)
	if ok || err != nil {
		t.Fatalf("not propagated: %v %v", ok, err)
	}
}
