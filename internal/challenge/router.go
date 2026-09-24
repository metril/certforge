package challenge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

// failFastTimeout and failFastInterval are what Router.Timeout returns once
// a name can no longer succeed (a Waiter failed, or the router's context is
// done), so lego stops polling the remaining names of the order quickly
// instead of for up to their normal propagation timeout.
const (
	failFastTimeout  = 5 * time.Second
	failFastInterval = time.Second
)

// ErrPropagationTimeout means a name's own per-name propagation budget
// (ruleTimeout) elapsed before its TXT record could be confirmed, regardless
// of how long Router.Timeout allows the whole order to be polled.
var ErrPropagationTimeout = errors.New("propagation check did not succeed within its budget")

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
	now   func() time.Time

	mu          sync.Mutex
	failedStep  map[string]bool      // "challenge "+name already reported StepFailed
	anyFailed   bool                 // at least one PreCheck has failed fast
	budgetStart map[string]time.Time // name -> when its per-name propagation budget started
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
	return &Router{ctx: ctx, names: ns, rules: slices.Clone(rules), sink: sink, now: time.Now}
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

// routingKey derives the certificate name used to select a rule from a lego
// callback's domain argument. Present and CleanUp always receive the bare
// authorization domain (acme.Authorization.Identifier.Value); PreCheck
// receives that same bare domain for an apex authorization, but the domain
// prefixed with "*." for a wildcard authorization (lego's
// challenge.GetTargetedDomain). Stripping a leading "*." before nameFor
// means all three land on the same rule for one authorization, matching the
// ADR: the apex rule serves both when both names are present.
func (r *Router) routingKey(domain string) string {
	return r.nameFor(strings.TrimPrefix(normalize(domain), "*."))
}

func (r *Router) route(domain string) (string, *Rule, error) {
	name := r.routingKey(domain)
	rule, ok := r.ruleFor(name)
	if !ok {
		return name, nil, fmt.Errorf("no verification rule matches %s", name)
	}
	return name, rule, nil
}

// ruleTimeout is the budget a name using rule gets for its propagation
// checks: rule.Timeout when the rule (or a level of issuance defaults) set
// one explicitly, otherwise the provider's own default (a lego DNS
// provider's *_PROPAGATION_TIMEOUT), falling back to
// dns01.DefaultPropagationTimeout if even that is unset (0) — never 0
// itself, or a per-name budget would be treated as already elapsed the
// instant it starts.
func ruleTimeout(rule *Rule) time.Duration {
	if rule.Timeout > 0 {
		return rule.Timeout
	}
	if t, _ := rule.Provider.Timeout(); t > 0 {
		return t
	}
	return dns01.DefaultPropagationTimeout
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
// the rules in use, plus the manual wait budget for manual rules whose
// Waiter has not yet returned. Once a name's Waiter returns (the operator
// confirmed, or it failed), that name switches to its own per-name
// propagation budget (see PreCheck), so its wait budget no longer needs to
// inflate this global value — only names still waiting on a human do. Once
// PreCheck has failed fast for any name (a Waiter failed, the router's
// context is done, or a per-name budget expired), it returns
// failFastTimeout/failFastInterval instead: lego's dns01.Solve reads
// Timeout() again for each remaining authorization of the order, so this is
// what stops it from also polling those for up to their normal timeout
// after one name can no longer succeed.
func (r *Router) Timeout() (time.Duration, time.Duration) {
	r.mu.Lock()
	failed := r.anyFailed
	r.mu.Unlock()
	if failed || r.ctx.Err() != nil {
		return failFastTimeout, failFastInterval
	}
	var longest time.Duration
	for _, n := range r.names {
		key := r.routingKey(n)
		rule, ok := r.ruleFor(key)
		if !ok {
			continue
		}
		t := ruleTimeout(rule)
		if w, ok := rule.Provider.(Waiter); ok && !r.budgetStarted(key) {
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

// budgetStarted reports whether name's per-name propagation budget has
// already started (its Waiter, if any, has returned; or, for a non-manual
// rule, PreCheck has already been called once for it).
func (r *Router) budgetStarted(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.budgetStart[name]
	return ok
}

// startBudget records name's propagation-budget start time, the first time
// it is called for that name.
func (r *Router) startBudget(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.budgetStart == nil {
		r.budgetStart = map[string]time.Time{}
	}
	if _, ok := r.budgetStart[name]; !ok {
		r.budgetStart[name] = r.now()
	}
}

// budgetExceeded reports whether name's per-name propagation budget (rule's
// ruleTimeout) has elapsed since startBudget was called for it.
func (r *Router) budgetExceeded(name string, rule *Rule) bool {
	r.mu.Lock()
	start, ok := r.budgetStart[name]
	r.mu.Unlock()
	if !ok {
		return false
	}
	return r.now().Sub(start) > ruleTimeout(rule)
}

// PreCheck is installed with dns01.WrapPreCheck. domain is lego's targeted
// domain for the authorization ("*.x" for a wildcard authorization, "x"
// otherwise); see routingKey.
//
// lego v4's platform/wait.For does not stop polling when PreCheck returns an
// error: it records the error and keeps calling PreCheck until its own
// timeout, and challenge.parallelSolve keeps the other authorizations of the
// same order running too. So once a Waiter has failed (a manual-dns timeout),
// a name's own propagation budget has expired, a CNAME alias mismatches, or
// the router's context is done, PreCheck cannot report that by returning an
// error without leaving this and every other name of the order polling for
// up to an hour (Router.Timeout returns one value for the whole order, the
// largest across every rule in use, so a name with a short rule timeout
// sharing an order with a long manual wait would otherwise be polled by lego
// for just as long). Instead PreCheck marks the step failed and reports
// ready (true, nil): lego proceeds straight to CA validation, which then
// fails the authorization for the real reason. Router.Timeout shrinks the
// same way so dns01.Solve does not keep polling the other names either.
// markFailed makes the step update idempotent, since the cached failure is
// reported again on every later PreCheck for this name.
//
// Once a name is past its Waiter (confirmed, or it has none), it gets its
// own propagation budget — ruleTimeout(rule), started by startBudget at that
// point — enforced here independently of Router.Timeout/lego's own outer
// polling loop; see budgetExceeded.
func (r *Router) PreCheck(domain, fqdn, value string, check func(fqdn, value string) (bool, error)) (bool, error) {
	name, rule, err := r.route(domain)
	if err != nil {
		return false, err
	}
	if w, ok := rule.Provider.(Waiter); ok {
		if werr := w.WaitReady(r.ctx); werr != nil {
			r.markFailed(name, werr)
			return true, nil
		}
		r.sink.Step("challenge "+name, StepRunning, "confirmed; checking propagation")
	}
	r.startBudget(name)
	if cerr := r.ctx.Err(); cerr != nil {
		r.markFailed(name, cerr)
		return true, nil
	}
	if r.budgetExceeded(name, rule) {
		r.markFailed(name, fmt.Errorf("%w: %s elapsed", ErrPropagationTimeout, ruleTimeout(rule)))
		return true, nil
	}
	if rule.AliasZone != "" {
		z := normalize(rule.AliasZone)
		f := normalize(fqdn)
		if f != z && !strings.HasSuffix(f, "."+z) {
			r.markFailed(name, fmt.Errorf("_acme-challenge for %s resolves to %s, not into alias zone %s: check the CNAME", name, f, z))
			return true, nil
		}
	}
	if len(rule.Resolvers) > 0 {
		return CheckTXT(r.ctx, rule.Resolvers, fqdn, value)
	}
	return check(fqdn, value)
}

// markFailed records StepFailed for name's step once; later calls for the
// same name (lego calling PreCheck again for the same authorization, or a
// second name sharing this failure) only refresh anyFailed, which is
// already true, so Timeout keeps returning the short values.
func (r *Router) markFailed(name string, cause error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.anyFailed = true
	if r.failedStep == nil {
		r.failedStep = map[string]bool{}
	}
	if r.failedStep[name] {
		return
	}
	r.failedStep[name] = true
	r.sink.Step("challenge "+name, StepFailed, failCause(cause))
}

// failCause names the cause of a PreCheck failure for the timeline: a
// manual-dns timeout or a cancelled/expired context.
func failCause(err error) string {
	switch {
	case errors.Is(err, ErrManualTimeout):
		return "manual-dns timed out: " + err.Error()
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled: " + err.Error()
	default:
		return err.Error()
	}
}
