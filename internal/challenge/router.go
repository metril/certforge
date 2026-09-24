package challenge

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

// Rule is one resolved verification rule.
type Rule struct {
	Matcher   Matcher
	Provider  ChallengeProvider
	Resolvers []string      // empty = lego's default propagation check
	Timeout   time.Duration // 0 = provider default
	AliasZone string        // expected CNAME target zone, "" = none
	Label     string        // shown in the timeline, e.g. "*.example.com → cloudflare-prod"
}

// Router dispatches lego DNS-01 callbacks to the first rule whose Matcher
// matches the certificate name. It implements lego's challenge.Provider and
// challenge.ProviderTimeout, and signer.ChallengeSolver.
type Router struct {
	ctx   context.Context
	names []string
	rules []Rule
	sink  StepSink
}

// NewRouter binds rules to the certificate names of one issuance. ctx is used
// for provider calls because lego v4's callbacks carry no context.
func NewRouter(ctx context.Context, names []string, rules []Rule, sink StepSink) *Router {
	if sink == nil {
		sink = NopSink{}
	}
	ns := make([]string, len(names))
	for i, n := range names {
		ns[i] = normalize(n)
	}
	return &Router{ctx: ctx, names: ns, rules: rules, sink: sink}
}

// Validate fails when a name is an IP address or no rule matches it, so an
// uncovered name is reported before any order is placed at the CA.
func (r *Router) Validate() error {
	var bad []string
	for _, n := range r.names {
		if net.ParseIP(n) != nil {
			return fmt.Errorf("IP address %s cannot be validated with DNS-01", n)
		}
		if _, ok := r.ruleFor(n); !ok {
			bad = append(bad, n)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("no verification rule matches %s and no catch-all rule is configured", strings.Join(bad, ", "))
	}
	return nil
}

func (r *Router) ruleFor(name string) (*Rule, bool) {
	for i := range r.rules {
		if r.rules[i].Matcher.Matches(name) {
			return &r.rules[i], true
		}
	}
	return nil, false
}

// nameFor maps lego's bare authorization domain back to a certificate name.
// lego passes "example.com" for both "example.com" and "*.example.com"; both
// use the TXT record _acme-challenge.example.com, so the apex rule wins when
// both names are present.
func (r *Router) nameFor(domain string) string {
	d := normalize(domain)
	if slices.Contains(r.names, d) {
		return d
	}
	if w := "*." + d; slices.Contains(r.names, w) {
		return w
	}
	return d
}

func (r *Router) route(domain string) (string, *Rule, error) {
	name := r.nameFor(domain)
	rule, ok := r.ruleFor(name)
	if !ok {
		return name, nil, fmt.Errorf("no verification rule matches %s", name)
	}
	return name, rule, nil
}

// Present implements lego challenge.Provider.
func (r *Router) Present(domain, token, keyAuth string) error {
	name, rule, err := r.route(domain)
	if err != nil {
		return err
	}
	step := "challenge " + name
	r.sink.Step(step, StepRunning, "presenting TXT via "+rule.Label)
	if err := rule.Provider.Present(r.ctx, domain, token, keyAuth); err != nil {
		r.sink.Step(step, StepFailed, err.Error())
		return err
	}
	if _, ok := rule.Provider.(Waiter); ok {
		r.sink.Step(step, StepWaitingManual, "waiting for the TXT records to be added and confirmed")
	} else {
		r.sink.Step(step, StepRunning, "TXT presented; checking propagation")
	}
	return nil
}

// CleanUp implements lego challenge.Provider.
func (r *Router) CleanUp(domain, token, keyAuth string) error {
	_, rule, err := r.route(domain)
	if err != nil {
		return err
	}
	return rule.Provider.CleanUp(r.ctx, domain, token, keyAuth)
}

// Timeout implements lego challenge.ProviderTimeout: the largest timeout of
// the rules in use, plus the manual wait budget for manual rules.
func (r *Router) Timeout() (time.Duration, time.Duration) {
	var longest time.Duration
	for _, n := range r.names {
		rule, ok := r.ruleFor(n)
		if !ok {
			continue
		}
		t := rule.Timeout
		if t == 0 {
			t, _ = rule.Provider.Timeout()
		}
		if w, ok := rule.Provider.(Waiter); ok {
			t += w.WaitBudget()
		}
		if t > longest {
			longest = t
		}
	}
	if longest == 0 {
		longest = dns01.DefaultPropagationTimeout
	}
	return longest, dns01.DefaultPollingInterval
}

// PreCheck is installed with dns01.WrapPreCheck. domain is the targeted
// certificate name ("*.x" for wildcards).
func (r *Router) PreCheck(domain, fqdn, value string, check func(fqdn, value string) (bool, error)) (bool, error) {
	name := normalize(domain)
	if !slices.Contains(r.names, name) {
		name = r.nameFor(strings.TrimPrefix(name, "*."))
	}
	rule, ok := r.ruleFor(name)
	if !ok {
		return false, fmt.Errorf("no verification rule matches %s", name)
	}
	if w, ok := rule.Provider.(Waiter); ok {
		if err := w.WaitReady(r.ctx); err != nil {
			return false, err
		}
		r.sink.Step("challenge "+name, StepRunning, "confirmed; checking propagation")
	}
	if rule.AliasZone != "" {
		z := normalize(rule.AliasZone)
		f := normalize(fqdn)
		if f != z && !strings.HasSuffix(f, "."+z) {
			return false, fmt.Errorf("_acme-challenge for %s resolves to %s, not into alias zone %s: check the CNAME", name, f, z)
		}
	}
	if len(rule.Resolvers) > 0 {
		return CheckTXT(r.ctx, rule.Resolvers, fqdn, value)
	}
	return check(fqdn, value)
}
