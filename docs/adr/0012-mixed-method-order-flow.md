# 0012: Mixed-method order flow

Status: accepted (Phase 4A)

## Context
Phase 4A (Task 6) made `challenge.Router` type-aware: `Router.For(t)` returns a view scoped to challenge type `t`, and `Router.ChallengeTypes()` reports the distinct types a certificate's names actually use. But lego v4's own `challenge.resolver.SolverManager.chooseSolver` picks a solver per authorization by a fixed type preference over the CA's offered challenges (dns-01, then http-01, then tls-alpn-01 by sort order) and never consults which domain the authorization is for (`challenge/resolver/solver_manager.go`). Registering more than one provider (say a dns-01 view and an http-01 view) with `lego.Client` does not make `Obtain` route each authorization to the rule that actually names it — every authorization of the order would reach whichever type sorts first, regardless of which rule covers its domain. Task 6 worked around this by rejecting a certificate whose names span more than one challenge type (`registerChallengeSolver`), leaving mixed dns-01/http-01/tls-alpn-01 certificates unsupported.

`lego.Client`'s own ACME core (`*api.Core`) is unexported, so nothing built on top of `lego.Client` can drive a custom per-authorization solver. `certificate.NewCertifier(core *api.Core, resolver, options)` (lego v4.24.0 `certificate/certificates.go:120-152`) is exported and accepts any value implementing `Solve(authorizations []acme.Authorization) error` in place of lego's own `SolverManager`/`Prober`. `core` itself is obtainable directly via the exported `api.New(httpClient, userAgent, caDirURL, kid, privateKey)`.

## Decision
A certificate whose names resolve to more than one challenge type (`req.Challenge.ChallengeTypes()` has more than one entry) is issued through `issueMixed` (`internal/signer/acme/orderflow.go`) instead of `lego.Client.Certificate.Obtain`:

- `api.New` builds the ACME core directly, bypassing `lego.Client` entirely.
- `mixedResolver` implements `Solve` for `certificate.NewCertifier`: per authorization, `pickChallenge` resolves the domain lego itself would target (`challenge.GetTargetedDomain`, already wildcard-prefixed) to a type via the rule solver's own `TypeFor`, then to the CA's matching offered challenge (`challenge.FindChallenge`) — an authorization the CA never offered that type for is a named error, and an already-valid authorization is skipped.
- Per type, the resolver drives lego's own exported challenge drivers — `dns01.NewChallenge`, `http01.NewChallenge`, `tlsalpn01.NewChallenge` — each given `solver.For(t)`, the same type-scoped view Task 6 built for the single-method path, so it can never reach a rule of a different type sharing a bare domain.
- Every dns-01 authorization is `PreSolve`d (TXT presented) before any authorization is `Solve`d, in the order lego returned them; `CleanUp` runs for the dns-01 authorizations only, since http-01/tls-alpn-01's own `Solve` presents, validates and cleans up in one call. A failure at any step stops the flow but still runs the dns-01 `CleanUp`s first.
- `validate` — the function each challenge driver calls once it has presented — is hand-written rather than reused from lego's unexported `challenge/resolver.validate`, which depends on `cenkalti/backoff` (not part of this dependency graph here): it POSTs `Challenges.New` once, then polls `Authorizations.Get` on a `time.Timer` honouring the challenge's own `Retry-After` (else 5s), bounded by a ctx 30s past the certifier timeout.
- `certificate.NewCertifier(core, res, options).Obtain(or)` then runs the same order, finalize, preferred-chain, must-staple and `ReplacesCertID` handling as the single-method path; `api.New` and `Obtain` errors both go through the existing `classify`.

A single-method certificate is unaffected: `Issue` still builds `lego.Client` and calls `registerChallengeSolver` + `Obtain`, unchanged.

## Consequences
- Two issuance paths exist in `internal/signer/acme` (`Obtain` via `lego.Client`, and `issueMixed` via `certificate.NewCertifier` directly), rather than one lego-managed path. They must be kept behaviourally aligned by hand — a change to bundling, must-staple, preferred chain or `ReplacesCertID` handling on one side needs the same change on the other.
- The hand-written `validate` duplicates (with a `time.Timer`/ctx instead of `cenkalti/backoff`) what lego's own unexported `challenge/resolver.validate` does; a lego upgrade that changes that polling behaviour will not automatically apply here.
- `mixedResolver`'s ctx-bound poll is the only timeout on challenge validation for a mixed-method order; lego's own `SolverManager`/`Prober.Timeout()` machinery (which Task 6's `Router.Timeout` feeds) is not consulted on this path.
