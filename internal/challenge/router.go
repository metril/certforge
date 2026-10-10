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

	"github.com/metril/certforge/internal/signer"
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
	refused     bool                 // a propagation check reported "returned REFUSED"
	usedResolv  bool                 // CheckTXT ran against configured resolvers
}

const (
	hintRefused  = "network appears to intercept DNS; set Settings → Issuance → Resolvers (e.g. https://cloudflare-dns.com/dns-query)"
	hintNegCache = "resolver may be caching a negative answer; use DoH resolvers or raise Propagation wait"
)

// Hint returns advice for a failed issuance whose error is err, based on
// what the propagation checks saw, or "" when there is none.
func (r *Router) Hint(err error) string {
	r.mu.Lock()
	refused, used := r.refused, r.usedResolv
	r.mu.Unlock()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	switch {
	case refused || strings.Contains(msg, "returned REFUSED"):
		return hintRefused
	case used && (strings.Contains(msg, "time limit exceeded") || errors.Is(err, ErrPropagationTimeout)):
		return hintNegCache
	}
	return ""
}

// noteCheckErr remembers a REFUSED answer from a propagation check.
func (r *Router) noteCheckErr(err error) {
	if err != nil && strings.Contains(err.Error(), "returned REFUSED") {
		r.mu.Lock()
		r.refused = true
		r.mu.Unlock()
	}
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

// Validate fails when a name is an IP address, or no rule matches it: for a
// wildcard name, ruleFor already skips any http-01/tls-alpn-01 rule in its
// path (no ACME CA offers those challenges for a wildcard authorization; see
// the controller ruling on ruleFor), so an uncovered wildcard is reported
// the same way as any other uncovered name, before any order is placed at
// the CA.
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

// ruleType is a rule's effective challenge type: manual-dns counts as
// dns-01 (same TXT-record mechanism, just operator-confirmed).
func ruleType(p ChallengeProvider) Type {
	if p.Type() == ManualDNS {
		return DNS01
	}
	return p.Type()
}

// ChallengeTypes returns the distinct challenge types r.names actually
// resolve to (each name's own ruleFor lookup; manual-dns counts as dns-01),
// in name order. A rule that matches none of the certificate's names — an
// inherited catch-all shadowed, for every name, by the certificate's own
// rules — does not appear here, so acme.Issue does not reject a certificate
// as spanning more than one challenge type over a rule its names never
// actually reach.
func (r *Router) ChallengeTypes() []string {
	seen := map[Type]bool{}
	var out []string
	for _, n := range r.names {
		rule, ok := r.ruleFor(n)
		if !ok {
			continue
		}
		t := ruleType(rule.Provider)
		if !seen[t] {
			seen[t] = true
			out = append(out, string(t))
		}
	}
	return out
}

// TypeFor returns the challenge type used for name, matched as given
// (unstripped): "*.example.com" stays a wildcard, so it reports the
// wildcard rule's own type rather than falling back to its apex.
func (r *Router) TypeFor(name string) (string, error) {
	rule, ok := r.ruleFor(normalize(name))
	if !ok {
		return "", fmt.Errorf("no verification rule matches %s", name)
	}
	return string(ruleType(rule.Provider)), nil
}

// For returns the view of the router restricted to challenge type t: its
// Present/CleanUp/PreCheck resolve a bare authorization domain to the rule
// of type t that covers it (see routeForType), rather than to whichever
// rule nameFor's apex-wins tie-break would otherwise pick — so a single
// registered lego provider (SetHTTP01Provider, SetDNS01Provider, ...) can
// never reach a rule of a different type sharing the same bare domain.
func (r *Router) For(t string) signer.ChallengeSolver {
	return &solverView{r: r, t: Type(t)}
}

// routeForType resolves domain to the rule of type t that covers it,
// checking both certificate names that could share domain as their bare
// ACME authorization identifier: domain itself, and "*."+domain (see
// nameFor/routingKey). This is what lets a type-scoped view reach the
// wildcard rule when the apex shares the same bare domain but uses a
// different type, and vice versa.
func (r *Router) routeForType(domain string, t Type) (string, *Rule, error) {
	base := strings.TrimPrefix(normalize(domain), "*.")
	for _, name := range []string{base, "*." + base} {
		if !slices.Contains(r.names, name) {
			continue
		}
		if rule, ok := r.ruleFor(name); ok && ruleType(rule.Provider) == t {
			return name, rule, nil
		}
	}
	return base, nil, fmt.Errorf("no %s verification rule matches %s", t, domain)
}

// solverView is the per-type ChallengeSolver returned by Router.For.
type solverView struct {
	r *Router
	t Type
}

func (v *solverView) Present(domain, token, keyAuth string) error {
	name, rule, err := v.r.routeForType(domain, v.t)
	if err != nil {
		return err
	}
	return v.r.present(name, rule, domain, token, keyAuth)
}

func (v *solverView) CleanUp(domain, token, keyAuth string) error {
	_, rule, err := v.r.routeForType(domain, v.t)
	if err != nil {
		return err
	}
	return rule.Provider.CleanUp(v.r.ctx, domain, token, keyAuth)
}

func (v *solverView) Timeout() (time.Duration, time.Duration) { return v.r.Timeout() }

// PreCheck resolves domain to the rule of v's own type (routeForType), not
// Router's type-blind, apex-wins route: for an apex rule of a different
// type sharing a bare domain with a wildcard rule of v's type, using route
// here would silently apply the apex rule's resolvers/AliasZone/budget (or
// lack of them) instead of the wildcard rule's own (fix round 1, Important
// finding; see TestSolverViewPreCheckUsesOwnTypeRule).
func (v *solverView) PreCheck(domain, fqdn, value string, check func(fqdn, value string) (bool, error)) (bool, error) {
	name, rule, err := v.r.routeForType(domain, v.t)
	if err != nil {
		return false, err
	}
	return v.r.preCheck(name, rule, fqdn, value, check)
}

func (v *solverView) ChallengeTypes() []string { return []string{string(v.t)} }

func (v *solverView) TypeFor(domain string) (string, error) {
	if _, _, err := v.r.routeForType(domain, v.t); err != nil {
		return "", err
	}
	return string(v.t), nil
}

func (v *solverView) For(t string) signer.ChallengeSolver { return v.r.For(t) }

// ruleFor returns the first rule matching name. Controller ruling: no ACME
// CA ever offers http-01 or tls-alpn-01 for a wildcard authorization, so
// when name is a wildcard ("*.zone"), a rule of either type is treated as
// not matching — routing skips it and tries the next matching rule in
// order — instead of matching it and then failing later. This is the single
// choke point every wildcard/method interaction goes through: Validate,
// TypeFor, ChallengeTypes and routeForType all resolve through ruleFor.
func (r *Router) ruleFor(name string) (*Rule, bool) {
	wildcard := strings.HasPrefix(name, "*.")
	for i := range r.rules {
		if !r.rules[i].Matcher.Matches(name) {
			continue
		}
		if wildcard {
			if t := ruleType(r.rules[i].Provider); t == HTTP01 || t == TLSALPN01 {
				continue
			}
		}
		return &r.rules[i], true
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
	return r.present(name, rule, domain, token, keyAuth)
}

// present runs rule's Provider.Present for name/domain, recording timeline
// steps with a message appropriate to the rule's challenge type. Shared by
// the unfiltered Router and its per-type views (solverView).
func (r *Router) present(name string, rule *Rule, domain, token, keyAuth string) error {
	step := "challenge " + name
	r.sink.Step(step, StepRunning, presentMessage(rule))
	if err := rule.Provider.Present(r.ctx, domain, token, keyAuth); err != nil {
		r.sink.Step(step, StepFailed, err.Error())
		return err
	}
	if _, ok := rule.Provider.(Waiter); ok {
		r.sink.Step(step, StepWaitingManual, "waiting for the TXT records to be added and confirmed")
	} else {
		r.sink.Step(step, StepRunning, doneMessage(rule))
	}
	return nil
}

// presentMessage is the "presenting" timeline message for rule, per its
// challenge type.
func presentMessage(rule *Rule) string {
	switch ruleType(rule.Provider) {
	case HTTP01:
		return "serving http-01 token via " + rule.Label
	case TLSALPN01:
		return "serving tls-alpn-01 certificate via " + rule.Label
	default:
		return "presenting TXT via " + rule.Label
	}
}

// doneMessage is the timeline message once Present has succeeded for a
// non-Waiter provider, per rule's challenge type.
func doneMessage(rule *Rule) string {
	switch ruleType(rule.Provider) {
	case HTTP01:
		return "http-01 token served"
	case TLSALPN01:
		return "tls-alpn-01 certificate served"
	default:
		return "TXT presented; checking propagation"
	}
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

// SettleDelay is how long a name using configured recursive resolvers waits,
// after its propagation budget starts, before the first query. Variable so
// tests can shorten it.
var SettleDelay = 20 * time.Second

// settling reports whether name is still inside its settle delay.
func (r *Router) settling(name string) bool {
	r.mu.Lock()
	start, ok := r.budgetStart[name]
	r.mu.Unlock()
	return ok && r.now().Sub(start) < SettleDelay
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
	return r.preCheck(name, rule, fqdn, value, check)
}

// preCheck runs the propagation/readiness check for name/rule. Shared by
// the unfiltered Router.PreCheck and solverView.PreCheck (which resolves
// name/rule via routeForType instead of route, so it never applies the
// wrong rule's settings for a domain shared across types; see solverView).
func (r *Router) preCheck(name string, rule *Rule, fqdn, value string, check func(fqdn, value string) (bool, error)) (bool, error) {
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
		cause := fmt.Errorf("%w: %s elapsed", ErrPropagationTimeout, ruleTimeout(rule))
		r.mu.Lock()
		used := r.usedResolv
		r.mu.Unlock()
		if h := r.Hint(cause); h != "" && (used || r.refusedSeen()) {
			cause = fmt.Errorf("%w; %s", cause, h)
		}
		r.markFailed(name, cause)
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
		// Querying a recursive resolver before the provider has published the
		// record can cache a negative answer for the zone's SOA minimum.
		if r.settling(name) {
			return false, nil
		}
		r.mu.Lock()
		r.usedResolv = true
		r.mu.Unlock()
		ok, err := CheckTXT(r.ctx, rule.Resolvers, fqdn, value)
		r.noteCheckErr(err)
		return ok, err
	}
	ok, err := check(fqdn, value)
	r.noteCheckErr(err)
	return ok, err
}

func (r *Router) refusedSeen() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refused
}

// markFailed records StepFailed for name's step once; later calls for the
// same name (lego calling PreCheck again for the same authorization, or a
// second name sharing this failure) only refresh anyFailed, which is
// already true, so Timeout keeps returning the short values.
func (r *Router) markFailed(name string, cause error) {
	r.mu.Lock()
	r.anyFailed = true
	if r.failedStep == nil {
		r.failedStep = map[string]bool{}
	}
	first := !r.failedStep[name]
	r.failedStep[name] = true
	r.mu.Unlock()
	// Reported after unlock: the sink may block or call back into the router.
	// failedStep was set under the lock, so only the first caller reports.
	if first {
		r.sink.Step("challenge "+name, StepFailed, failCause(cause))
	}
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
