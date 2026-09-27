package acme

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	legochallenge "github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"

	"github.com/metril/certforge/internal/signer"
)

// certifierTimeout is certificate.CertifierOptions.Timeout for a
// mixed-method order: lego's own order finalization/download polling, once
// Solve has returned. It has nothing to do with challenge validation: see
// validate, which bounds each of its own poll loops independently.
const certifierTimeout = 30 * time.Second

// resolver mirrors certificate.resolver's method set (unexported in lego, so
// it cannot be named here) as a named type of our own, only so newCertifier
// below has a signature tests can substitute; mixedResolver's Solve method
// alone already satisfies lego's own unexported interface structurally.
type resolver interface {
	Solve(authorizations []legoacme.Authorization) error
}

// newCertifier wraps certificate.NewCertifier, indirected through a package
// var of a nameable signature so TestIssueSingleTypeKeepsSolverManager can
// substitute a hook and assert that a single-challenge-type Issue never
// takes this mixed order-flow path.
var newCertifier = func(core *api.Core, res resolver, opts certificate.CertifierOptions) *certificate.Certifier {
	return certificate.NewCertifier(core, res, opts)
}

// issueMixed drives an order whose names resolve to more than one challenge
// type (ADR 0012): lego's SolverManager.chooseSolver picks a solver per
// authorization by a fixed type preference and never consults the domain, so
// a single registered provider cannot reach more than one rule type across a
// certificate's names (Issue calls registerChallengeSolver, which only
// handles exactly one type, for everything else). This builds the ACME core
// directly with api.New because lego.Client's own core is unexported, and
// drives certificate.NewCertifier with a mixedResolver that picks each
// authorization's method from req.Challenge itself.
//
// mixedResolver.ctx is ctx itself, unwrapped: there is no order-wide
// deadline layered on top of it here (fix round 1, Important). An earlier
// version bounded it with context.WithTimeout(ctx, certifierTimeout+30s),
// computed once before Solve ran; that one shared clock also covered every
// PreSolve, DNS propagation wait and manual-dns WaitBudget Solve might do
// first, so a slow rule could leave validate with little or none of that
// budget left by the time it was finally called, failing "context deadline
// exceeded" even for a challenge that would otherwise have validated
// quickly. validate now derives its own fresh bound from ctx per call (see
// validate) instead.
func (s *Signer) issueMixed(ctx context.Context, u *user, kt certcrypto.KeyType, req signer.IssueRequest) (*signer.Issued, error) {
	hc, rt, err := s.httpClient(ctx)
	if err != nil {
		return nil, err
	}
	core, err := api.New(hc, s.cfg.UserAgent, s.cfg.DirectoryURL, u.reg.URI, u.key)
	if err != nil {
		return nil, classify(err, rt)
	}

	or, err := obtainRequest(req)
	if err != nil {
		return nil, err
	}

	res := &mixedResolver{core: core, solver: req.Challenge, ctx: ctx}
	certifier := newCertifier(core, res, certificate.CertifierOptions{KeyType: kt, Timeout: certifierTimeout})
	out, err := certifier.Obtain(or)
	if err != nil {
		return nil, classify(err, rt)
	}
	return signer.IssuedFromPEM(out.Certificate, out.PrivateKey)
}

// mixedResolver implements lego's certificate.resolver (Solve(authorizations
// []acme.Authorization) error) for an order spanning more than one challenge
// type. It never registers with lego's own SolverManager. ctx is the Issue
// caller's own ctx, unwrapped (see issueMixed); validate derives its own
// per-call bound from it rather than sharing one deadline across all of
// Solve.
type mixedResolver struct {
	core   *api.Core
	solver signer.ChallengeSolver
	ctx    context.Context
}

// authChallenge is one authorization paired with the challenge driver
// (dns01/http01/tlsalpn01) chosen for it by pickChallenge. dns is set only
// for a dns-01 authorization: unlike http-01/tls-alpn-01, whose own Solve
// presents, validates and cleans up the challenge in one call, dns-01's
// PreSolve (present) and CleanUp are run separately so every dns-01 name's
// TXT record can be presented before any of them is validated.
type authChallenge struct {
	authz legoacme.Authorization
	solve func(legoacme.Authorization) error
	dns   *dns01.Challenge
}

// pickChallenge selects the ACME challenge authz's rule uses: the domain lego
// itself would target (legochallenge.GetTargetedDomain, already carrying the
// "*." prefix for a wildcard authorization) resolved to a type via
// solver.TypeFor, then the matching entry in the CA's offered challenges. An
// already-valid authorization (skip=true) is not resolved at all: Boulder can
// recycle a recently validated authorization, and there is then no rule
// lookup to do.
func pickChallenge(solver signer.ChallengeSolver, authz legoacme.Authorization) (t string, chlg legoacme.Challenge, skip bool, err error) {
	if authz.Status == legoacme.StatusValid {
		return "", legoacme.Challenge{}, true, nil
	}
	domain := legochallenge.GetTargetedDomain(authz)
	t, err = solver.TypeFor(domain)
	if err != nil {
		return "", legoacme.Challenge{}, false, err
	}
	chlg, err = legochallenge.FindChallenge(legochallenge.Type(t), authz)
	if err != nil {
		return "", legoacme.Challenge{}, false, fmt.Errorf("CA offered no %s challenge for %s", t, domain)
	}
	return t, chlg, false, nil
}

// Solve implements lego's certificate.resolver. It builds one challenge
// driver per authorization up front (so a missing-type error is caught
// before anything is presented), then runs every dns-01 PreSolve (present
// the TXT records), then Solve for every authorization in the order lego
// gave them (http-01/tls-alpn-01's own Solve presents, validates and cleans
// up in that one call), then CleanUp for the dns-01 authorizations. It stops
// at the first error but still runs the dns-01 CleanUps first.
func (m *mixedResolver) Solve(authorizations []legoacme.Authorization) error {
	var entries []authChallenge
	for _, authz := range authorizations {
		t, _, skip, err := pickChallenge(m.solver, authz)
		if skip {
			continue
		}
		if err != nil {
			return err
		}
		switch t {
		case "dns-01":
			view := m.solver.For("dns-01")
			c := dns01.NewChallenge(m.core, m.validate, view, dns01.WrapPreCheck(
				func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
					return view.PreCheck(domain, fqdn, value, check)
				}))
			entries = append(entries, authChallenge{authz: authz, solve: c.Solve, dns: c})
		case "http-01":
			c := http01.NewChallenge(m.core, m.validate, m.solver.For("http-01"))
			entries = append(entries, authChallenge{authz: authz, solve: c.Solve})
		case "tls-alpn-01":
			c := tlsalpn01.NewChallenge(m.core, m.validate, m.solver.For("tls-alpn-01"))
			entries = append(entries, authChallenge{authz: authz, solve: c.Solve})
		default:
			return fmt.Errorf("unsupported challenge type %q for %s", t, legochallenge.GetTargetedDomain(authz))
		}
	}

	// A real dns-01 rule's provider is always challenge.WrapLego-wrapped, so
	// a live CleanUp failure below is already scrubbed of its rule's own
	// secrets (WrapLego calls challenge.Scrub before the error ever reaches
	// the Router, and therefore before it reaches this mixedResolver) by the
	// time it gets here — safe to log as-is, the same non-fatal warning
	// lego's own resolver.cleanUp logs for a failed CleanUp (fix round 1,
	// Minor).
	cleanupDNS := func() {
		for _, e := range entries {
			if e.dns == nil {
				continue
			}
			if err := e.dns.CleanUp(e.authz); err != nil {
				slog.Default().Warn("acme: dns-01 clean up failed",
					"domain", legochallenge.GetTargetedDomain(e.authz), "err", err)
			}
		}
	}

	for _, e := range entries {
		if e.dns == nil {
			continue
		}
		if err := e.dns.PreSolve(e.authz); err != nil {
			cleanupDNS()
			return err
		}
	}

	for _, e := range entries {
		if err := e.solve(e.authz); err != nil {
			cleanupDNS()
			return err
		}
	}

	cleanupDNS()
	return nil
}

// validate is our own replacement for lego's unexported
// challenge/resolver.validate: the global constraints forbid a new
// cenkalti/backoff import (lego's own resolver package uses it, but that
// package is not part of our dependency graph here), so this hand-rolls the
// same POST-then-poll with a time.Timer instead. It posts Challenges.New
// once; if the challenge is already decided, it returns immediately.
// Otherwise it polls Authorizations.Get at the challenge's own RetryAfter
// interval (else 5s) until the authorization is valid, invalid, or its own
// per-call budget (100x that interval, the same multiple lego's own
// validate bounds cenkalti/backoff's MaxElapsedTime by) elapses. That budget
// is a fresh context.WithTimeout derived from m.ctx (the Issue caller's own
// ctx) each time validate is called — not one deadline shared across all of
// Solve (fix round 1, Important) — so a slow PreSolve or DNS propagation
// wait elsewhere in Solve cannot eat into it.
func (m *mixedResolver) validate(core *api.Core, domain string, chlg legoacme.Challenge) error {
	chlng, err := core.Challenges.New(chlg.URL)
	if err != nil {
		return fmt.Errorf("[%s] acme: failed to initiate challenge: %w", domain, err)
	}
	switch chlng.Status {
	case legoacme.StatusValid:
		return nil
	case legoacme.StatusInvalid:
		return chlng.Err()
	}

	interval := 5 * time.Second
	if ra, err := strconv.Atoi(chlng.RetryAfter); err == nil && ra > 0 {
		interval = time.Duration(ra) * time.Second
	}

	valCtx, cancel := context.WithTimeout(m.ctx, 100*interval)
	defer cancel()

	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-valCtx.Done():
			return fmt.Errorf("[%s] acme: %w", domain, valCtx.Err())
		case <-timer.C:
		}

		authz, err := core.Authorizations.Get(chlng.AuthorizationURL)
		if err != nil {
			return err
		}
		switch authz.Status {
		case legoacme.StatusValid:
			return nil
		case legoacme.StatusPending, legoacme.StatusProcessing:
			timer.Reset(interval)
		case legoacme.StatusInvalid:
			for _, c := range authz.Challenges {
				if c.Status == legoacme.StatusInvalid && c.Error != nil {
					return c.Err()
				}
			}
			return fmt.Errorf("[%s] acme: invalid authorization", domain)
		default:
			return fmt.Errorf("[%s] acme: unexpected authorization status: %s", domain, authz.Status)
		}
	}
}
