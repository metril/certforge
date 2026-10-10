package challenge

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
)

var routerTestNow = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

type recProvider struct {
	name    string
	typ     Type // zero value means DNS01
	mu      sync.Mutex
	present []string
	timeout time.Duration
}

func (p *recProvider) Type() Type {
	if p.typ == "" {
		return DNS01
	}
	return p.typ
}
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

// Review Focus (fix wave item 2): lego's wait.For ignores a PreCheck error
// and keeps polling until its own (much longer) timeout, so a CNAME alias
// mismatch — like a manual-dns timeout — must fail fast (report ready and
// mark the step failed) instead of returning an error lego would just keep
// retrying against.
func TestRouterPreCheckAliasZone(t *testing.T) {
	sink := &sinkRec{}
	ru := rule(t, "example.com", &recProvider{timeout: time.Minute})
	ru.AliasZone = "acme.example.net"
	step := "challenge example.com"
	r := NewRouter(context.Background(), []string{"example.com"}, []Rule{ru}, sink)
	ok, err := r.PreCheck("example.com", "_acme-challenge.example.com.", "v", func(string, string) (bool, error) { return true, nil })
	if !ok || err != nil {
		t.Fatalf("PreCheck must fail fast (true, nil), not return an error: %v, %v", ok, err)
	}
	if sink.steps[step] != StepFailed {
		t.Fatalf("step = %q", sink.steps[step])
	}
	if msg := sink.lastMessage(step); !strings.Contains(msg, "alias zone") {
		t.Fatalf("message should name the alias mismatch: %q", msg)
	}
	if got, iv := r.Timeout(); got != failFastTimeout || iv != failFastInterval {
		t.Fatalf("router Timeout after alias mismatch = %v, %v", got, iv)
	}

	sink2 := &sinkRec{}
	r2 := NewRouter(context.Background(), []string{"example.com"}, []Rule{ru}, sink2)
	ok, err = r2.PreCheck("example.com", "example.com.acme.example.net.", "v", func(string, string) (bool, error) { return true, nil })
	if !ok || err != nil {
		t.Fatalf("PreCheck in alias zone = %v, %v", ok, err)
	}
	if sink2.steps[step] == StepFailed {
		t.Fatal("a matching CNAME must not be marked failed")
	}
}

// Review Focus (fix wave item 2): a name's per-name propagation budget
// (ruleTimeout) starts at its first PreCheck and fails fast once it elapses,
// independent of Router.Timeout's own (order-wide) value — this is what
// keeps a name with a short rule timeout from being polled by lego for as
// long as a much longer rule shares its order (see the mixed-rule test
// below).
func TestRouterPreCheckBudgetExpires(t *testing.T) {
	sink := &sinkRec{}
	prov := &recProvider{timeout: 20 * time.Millisecond}
	ru := rule(t, "example.com", prov)
	step := "challenge example.com"
	r := NewRouter(context.Background(), []string{"example.com"}, []Rule{ru}, sink)
	clock := routerTestNow
	r.now = func() time.Time { return clock }
	check := func(string, string) (bool, error) { return false, nil } // never propagates

	ok, err := r.PreCheck("example.com", "_acme-challenge.example.com.", "v", check)
	if ok || err != nil {
		t.Fatalf("first PreCheck (budget just started) = %v, %v", ok, err)
	}
	if sink.steps[step] == StepFailed {
		t.Fatal("must not fail before the budget elapses")
	}

	clock = clock.Add(21 * time.Millisecond)
	ok, err = r.PreCheck("example.com", "_acme-challenge.example.com.", "v", check)
	if !ok || err != nil {
		t.Fatalf("PreCheck after the budget elapsed = %v, %v", ok, err)
	}
	if sink.steps[step] != StepFailed {
		t.Fatalf("step = %q", sink.steps[step])
	}
	if msg := sink.lastMessage(step); !strings.Contains(msg, "propagation") {
		t.Fatalf("message should name the propagation budget: %q", msg)
	}
}

// Review Focus (fix wave item 2): a dns-01 name sharing an order with a
// long manual-dns wait must not be polled for as long as the manual name;
// its own (short) rule budget fails it fast regardless of Router.Timeout's
// order-wide value, which is driven by the manual rule.
func TestRouterMixedRuleBudgetFailsIndependentlyOfLongerRule(t *testing.T) {
	store := &memManual{}
	mp := NewManual(store, uuid.New(), uuid.New())
	mp.Wait = time.Hour
	dnsProv := &recProvider{timeout: 20 * time.Millisecond}
	dnsRule := rule(t, "dns.example.com", dnsProv)
	manualRule := rule(t, "manual.example.com", mp)
	sink := &sinkRec{}
	names := []string{"dns.example.com", "manual.example.com"}
	r := NewRouter(context.Background(), names, []Rule{dnsRule, manualRule}, sink)
	clock := routerTestNow
	r.now = func() time.Time { return clock }
	check := func(string, string) (bool, error) { return false, nil } // never propagates
	step := "challenge dns.example.com"

	if before, _ := r.Timeout(); before < mp.Wait {
		t.Fatalf("order-wide Timeout should be driven by the manual rule's wait budget: %v", before)
	}
	ok, err := r.PreCheck("dns.example.com", "_acme-challenge.dns.example.com.", "v", check)
	if ok || err != nil {
		t.Fatalf("first PreCheck = %v, %v", ok, err)
	}
	clock = clock.Add(21 * time.Millisecond)
	ok, err = r.PreCheck("dns.example.com", "_acme-challenge.dns.example.com.", "v", check)
	if !ok || err != nil {
		t.Fatalf("PreCheck after the dns-01 name's own budget elapsed = %v, %v", ok, err)
	}
	if sink.steps[step] != StepFailed {
		t.Fatalf("step = %q", sink.steps[step])
	}
	if got, iv := r.Timeout(); got != failFastTimeout || iv != failFastInterval {
		t.Fatalf("router Timeout after the failure = %v, %v", got, iv)
	}
}

// Review Focus (fix wave item 2): Timeout must stop adding the manual wait
// budget for a name once its Waiter has returned (the operator confirmed),
// so lego's own outer polling loop shrinks back toward the propagation
// timeout instead of still allowing up to the full (already-spent) wait.
func TestRouterTimeoutDropsManualWaitBudgetAfterConfirm(t *testing.T) {
	store := &memManual{}
	store.confirm()
	r, mp, _ := manualRouter(t, store, time.Hour)
	if err := r.Present("lab.example.test", "tok", "keyauth"); err != nil {
		t.Fatal(err)
	}
	before, _ := r.Timeout()
	if before < mp.Wait {
		t.Fatalf("before confirm, Timeout must include the wait budget: %v", before)
	}
	ok, err := r.PreCheck("lab.example.test", "_acme-challenge.lab.example.test.", "v", func(string, string) (bool, error) { return true, nil })
	if !ok || err != nil {
		t.Fatalf("PreCheck = %v, %v", ok, err)
	}
	after, _ := r.Timeout()
	if after >= mp.Wait {
		t.Fatalf("after confirm, Timeout must drop the wait budget: %v", after)
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

func setSettle(t *testing.T, d time.Duration) {
	t.Helper()
	old := SettleDelay
	SettleDelay = d
	t.Cleanup(func() { SettleDelay = old })
}

func TestRouterPreCheckSettleDelay(t *testing.T) {
	setSettle(t, 20*time.Second)
	addr := startDNS(t, map[string]string{"_acme-challenge.example.com.": "good"})
	ru := rule(t, "example.com", &recProvider{})
	ru.Resolvers = []string{addr}
	r := NewRouter(context.Background(), []string{"example.com"}, []Rule{ru}, nil)
	clock := routerTestNow
	r.now = func() time.Time { return clock }
	legoCheck := func(string, string) (bool, error) { return false, errors.New("must not run") }

	ok, err := r.PreCheck("example.com", "_acme-challenge.example.com.", "good", legoCheck)
	if ok || err != nil {
		t.Fatalf("inside settle delay: %v %v", ok, err)
	}
	clock = clock.Add(19 * time.Second)
	if ok, _ := r.PreCheck("example.com", "_acme-challenge.example.com.", "good", legoCheck); ok {
		t.Fatal("still inside settle delay")
	}
	clock = clock.Add(2 * time.Second)
	if ok, err := r.PreCheck("example.com", "_acme-challenge.example.com.", "good", legoCheck); !ok || err != nil {
		t.Fatalf("after settle delay: %v %v", ok, err)
	}
}

func TestRouterPreCheckUsesRuleResolvers(t *testing.T) {
	setSettle(t, 0)
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

// TestRouterChallengeTypes: dns-01 + manual-dns both count as dns-01
// (manual-dns shares the TXT mechanism); a distinct http-01 rule adds to the
// set. TypeFor reports the type per name.
func TestRouterChallengeTypes(t *testing.T) {
	store := &memManual{}
	mp := NewManual(store, uuid.New(), uuid.New())
	r := NewRouter(context.Background(), []string{"a.example.com", "b.example.com"},
		[]Rule{rule(t, "a.example.com", &recProvider{}), rule(t, "b.example.com", mp)}, nil)
	got := r.ChallengeTypes()
	if len(got) != 1 || got[0] != string(DNS01) {
		t.Fatalf("dns-01+manual-dns ChallengeTypes = %v, want [dns-01]", got)
	}
	if typ, err := r.TypeFor("a.example.com"); err != nil || typ != string(DNS01) {
		t.Fatalf("TypeFor(a) = %q, %v", typ, err)
	}

	r2 := NewRouter(context.Background(), []string{"a.example.com", "b.example.com"},
		[]Rule{rule(t, "a.example.com", &recProvider{typ: HTTP01}), rule(t, "b.example.com", &recProvider{})}, nil)
	got2 := r2.ChallengeTypes()
	if len(got2) != 2 {
		t.Fatalf("http-01+dns-01 ChallengeTypes = %v, want both", got2)
	}
	if typ, err := r2.TypeFor("a.example.com"); err != nil || typ != string(HTTP01) {
		t.Fatalf("TypeFor(a) = %q, %v", typ, err)
	}
	if typ, err := r2.TypeFor("b.example.com"); err != nil || typ != string(DNS01) {
		t.Fatalf("TypeFor(b) = %q, %v", typ, err)
	}
}

// TestRouterMixedApexWildcard: an apex rule using http-01 listed first, a
// wildcard rule using dns-01 listed second, for the same zone. The
// controller ruling means "first match wins" does not apply unmodified to a
// wildcard name against an http-01/tls-alpn-01 rule: such a rule can never
// prove a wildcard, so a wildcard name skips it and matches the next rule in
// order — here the wildcard rule, even though the (broader) apex zone
// matcher listed first would otherwise have matched "*.example.com" too
// (matchZone matches wildcards below its zone). Validate must pass, TypeFor
// must report the wildcard name's own (unstripped) type, and For(type) must
// let each type's view reach only its own provider for the shared bare
// domain.
func TestRouterMixedApexWildcard(t *testing.T) {
	httpProv := &recProvider{typ: HTTP01}
	dnsProv := &recProvider{typ: DNS01}
	rules := []Rule{rule(t, "example.com", httpProv), rule(t, "*.example.com", dnsProv)}
	r := NewRouter(context.Background(), []string{"example.com", "*.example.com"}, rules, nil)

	if err := r.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if typ, err := r.TypeFor("*.example.com"); err != nil || typ != string(DNS01) {
		t.Fatalf("TypeFor(*.example.com) = %q, %v", typ, err)
	}
	if typ, err := r.TypeFor("example.com"); err != nil || typ != string(HTTP01) {
		t.Fatalf("TypeFor(example.com) = %q, %v", typ, err)
	}

	if err := r.For(string(DNS01)).Present("example.com", "t", "k"); err != nil {
		t.Fatal(err)
	}
	if len(dnsProv.present) != 1 || len(httpProv.present) != 0 {
		t.Fatalf("dns-01 view must reach the wildcard rule's provider: dns=%v http=%v", dnsProv.present, httpProv.present)
	}
	if err := r.For(string(HTTP01)).Present("example.com", "t", "k"); err != nil {
		t.Fatal(err)
	}
	if len(httpProv.present) != 1 || len(dnsProv.present) != 1 {
		t.Fatalf("http-01 view must reach the apex rule's provider: dns=%v http=%v", dnsProv.present, httpProv.present)
	}
}

// TestRouterRejectsWildcardNonDNS: a wildcard name cannot be proven with
// http-01 or tls-alpn-01 (the CA never offers those challenges for a
// wildcard authorization), so Validate must reject it even though the name
// is otherwise covered.
func TestRouterRejectsWildcardNonDNS(t *testing.T) {
	r := NewRouter(context.Background(), []string{"*.example.com"},
		[]Rule{rule(t, "*.example.com", &recProvider{typ: HTTP01})}, nil)
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "*.example.com") {
		t.Fatalf("Validate() = %v, want a wildcard/http-01 error", err)
	}
}

// TestRouterChallengeTypesIgnoresUnusedCatchAll (fix round 1, Important
// finding): ChallengeTypes must reflect only the rules r.names actually
// resolve to, not every rule in the list. An inherited "* -> http-01"
// catch-all that never actually matches anything (the certificate's own
// dns-01 rule shadows it for every one of its names, first-match-wins) must
// not appear, or a certificate fully served by dns-01 would be wrongly
// rejected by acme.Issue as spanning more than one challenge type.
func TestRouterChallengeTypesIgnoresUnusedCatchAll(t *testing.T) {
	r := NewRouter(context.Background(), []string{"example.com"},
		[]Rule{rule(t, "example.com", &recProvider{}), rule(t, "*", &recProvider{typ: HTTP01})}, nil)
	got := r.ChallengeTypes()
	if len(got) != 1 || got[0] != string(DNS01) {
		t.Fatalf("ChallengeTypes = %v, want [dns-01] (the unused http-01 catch-all must not count)", got)
	}
}

// TestSolverViewPreCheckUsesOwnTypeRule (fix round 1, Important finding):
// solverView.PreCheck must resolve via routeForType, not the type-blind
// Router.route (apex-wins). For an apex http-01 rule and a wildcard dns-01
// rule sharing a bare domain, the dns-01 view's PreCheck for the wildcard
// authorization must use the wildcard rule's own settings (here, AliasZone)
// — not silently pass because the apex rule (wrongly used) has none.
func TestSolverViewPreCheckUsesOwnTypeRule(t *testing.T) {
	httpProv := &recProvider{typ: HTTP01}
	dnsProv := &recProvider{typ: DNS01}
	apex := rule(t, "example.com", httpProv)
	wild := rule(t, "*.example.com", dnsProv)
	wild.AliasZone = "alias.example.net"
	sink := &sinkRec{}
	r := NewRouter(context.Background(), []string{"example.com", "*.example.com"}, []Rule{apex, wild}, sink)
	view := r.For(string(DNS01))

	// lego passes the wildcard-prefixed targeted domain to PreCheck for a
	// wildcard authorization (see routingKey's doc comment).
	ok, err := view.PreCheck("*.example.com", "_acme-challenge.example.com.", "v", func(string, string) (bool, error) { return true, nil })
	if !ok || err != nil {
		t.Fatalf("PreCheck must fail fast (true, nil) on the alias mismatch: %v, %v", ok, err)
	}
	step := "challenge *.example.com"
	if sink.steps[step] != StepFailed {
		t.Fatalf("must be routed to the wildcard rule's AliasZone check, not silently pass via the apex rule: step = %q", sink.steps[step])
	}
	if msg := sink.lastMessage(step); !strings.Contains(msg, "alias zone") {
		t.Fatalf("message should name the alias mismatch: %q", msg)
	}
}

// reentrantSink calls back into the router from Step, which deadlocks if
// markFailed still holds r.mu while it reports.
type reentrantSink struct {
	sinkRec
	r *Router
}

func (s *reentrantSink) Step(name, status, message string) {
	s.r.Timeout()
	s.sinkRec.Step(name, status, message)
}

// markFailed must not hold r.mu across sink.Step, and concurrent calls for
// one name must still report exactly one failure step.
func TestMarkFailedReportsOnceWithoutHoldingLock(t *testing.T) {
	sink := &reentrantSink{}
	r := NewRouter(context.Background(), []string{"example.com"}, []Rule{rule(t, "example.com", &recProvider{timeout: time.Minute})}, sink)
	sink.r = r
	step := "challenge example.com"
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.markFailed("example.com", errors.New("boom"))
			}()
		}
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("markFailed deadlocked: sink.Step ran under r.mu")
	}
	if n := sink.count(step, StepFailed); n != 1 {
		t.Fatalf("failure step reported %d times, want 1", n)
	}
	if got, _ := r.Timeout(); got != failFastTimeout {
		t.Fatalf("Timeout = %v, want fail-fast", got)
	}
}
