package issuance

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime/debug"
	"strings"
	"time"

	legochallenge "github.com/go-acme/lego/v4/challenge"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/metrics"
	"github.com/metril/certforge/internal/signer"
)

// IssueArgs is the river job issuing one certificate.
type IssueArgs struct {
	CertID uuid.UUID `json:"cert_id"`
}

// Kind implements river.JobArgs.
func (IssueArgs) Kind() string { return "certforge_issue" }

// InsertOpts makes the job unique per certificate while queued or running.
// Completed is deliberately excluded so a later renewal can be inserted.
func (IssueArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending,
				rivertype.JobStateRunning, rivertype.JobStateRetryable, rivertype.JobStateScheduled},
		},
	}
}

// VersionListener hears about each newly stored certificate version after
// its transaction commits. Phase 3 registers the agent service (deployment
// digests and sync nudges); Phase 6 notifiers reuse it. OnVersion cannot
// fail the issuance: errors are the listener's to log.
type VersionListener interface {
	OnVersion(ctx context.Context, certID, versionID uuid.UUID)
}

// IssueWorker runs one issuance attempt. ACME and challenge failures are
// recorded on the attempt and scheduled via next_renew_at; only
// infrastructure errors (database) are returned for river to retry.
type IssueWorker struct {
	river.WorkerDefaults[IssueArgs]
	Store *Store
	Certs *certstore.Store
	// NewSigner builds the signer for a CA (SignerFactory.New in
	// production): nil means every attempt fails immediately. Set before
	// riverClient.Start, same as HTTPTokens/Relay/CAA/Settings below.
	NewSigner  func(ctx context.Context, ca CA) (signer.Signer, error)
	BuildDNS   func(code string, cfg map[string]string) (legochallenge.Provider, error)
	Now        func() time.Time
	Rand       func() float64
	ManualWait time.Duration // 0 = challenge.DefaultManualWait
	ManualPoll time.Duration // 0 = 2s
	Log        *slog.Logger
	Listeners  []VersionListener // called after a version commits
	// OnFailure is called after fail's own writes commit, for every failed
	// attempt (nil means no listener, the same convention as Listeners
	// being empty). Set before riverClient.Start; see
	// cmd/certforge/serve.go.
	OnFailure FailureListener

	// HTTPTokens backs a server http-01 rule (via: server, the default):
	// nil means server http-01 is not wired up, so such a rule fails.
	// Shared with api.Deps.HTTPTokens; see cmd/certforge/serve.go.
	HTTPTokens *challenge.HTTPTokens

	// Relay backs an http-01 (via: agent) or tls-alpn-01 rule: nil means the
	// agent challenge relay is not wired up, so such a rule fails. Set to
	// the agents service (which implements challenge.AgentRelay) before
	// riverClient.Start; see cmd/certforge/serve.go.
	Relay challenge.AgentRelay

	// CAA resolves CAA record sets for the caa step. nil means
	// DNSCAAResolver, the production default; tests inject a fake.
	CAA CAAResolver

	// Settings loads the global "issuance" section fresh for each attempt
	// (CAA checking, rate limits). nil means the built-in defaults (CAA
	// checking on) — tests only; production sets this before
	// riverClient.Start, see cmd/certforge/serve.go.
	Settings func(ctx context.Context) (IssuanceSettings, error)

	// ARI polls the ACME Renewal Information window right after a
	// successful issuance commits (Task 12): nil skips the post-issuance
	// poll entirely (tests only); production sets this before
	// riverClient.Start, same as HTTPTokens/Relay/CAA/Settings above.
	ARI *ARIPollWorker
}

// NewIssueWorker wires production defaults. NewSigner is left nil: the
// caller wires it to a *SignerFactory before riverClient.Start, same as
// HTTPTokens/Relay/CAA/Settings.
func NewIssueWorker(store *Store, certs *certstore.Store) *IssueWorker {
	return &IssueWorker{Store: store, Certs: certs, BuildDNS: challenge.Build,
		Now: time.Now, Rand: rand.Float64, Log: slog.Default()}
}

// Timeout covers a manual-dns wait plus propagation and finalisation.
func (w *IssueWorker) Timeout(*river.Job[IssueArgs]) time.Duration { return 3 * time.Hour }

// saveTimeout bounds a single attempt-progress save (SaveAttemptProgress):
// without it, a stalled connection would hang inside Timeline.Step/Logf,
// which run synchronously on every challenge callback, for as long as the
// surrounding context allows — unbounded for bg (context.WithoutCancel).
const saveTimeout = 5 * time.Second

// maxPanicStackBytes bounds how much of a recovered panic's stack trace
// goes into the attempt log; the full trace can run to tens of KiB and
// would otherwise dominate maxLogBytes on its own.
const maxPanicStackBytes = 4 * 1024

// truncatedStack returns the current goroutine's stack trace, capped at
// maxPanicStackBytes with a trailing marker when it was cut short.
func truncatedStack() []byte { return truncateBytes(debug.Stack(), maxPanicStackBytes) }

// truncateBytes returns the first max bytes of b, with a trailing marker
// when b was longer than that.
func truncateBytes(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	out := make([]byte, 0, max+32)
	out = append(out, b[:max]...)
	out = append(out, []byte("\n...[stack truncated]")...)
	return out
}

// Work implements river.Worker.
func (w *IssueWorker) Work(ctx context.Context, job *river.Job[IssueArgs]) error {
	return w.Issue(ctx, job.Args.CertID)
}

// Issue performs one attempt for certID.
func (w *IssueWorker) Issue(ctx context.Context, certID uuid.UUID) error {
	// start bounds certforge_issuance_duration_seconds (metrics.
	// IssuanceDuration): captured before CreateAttempt so the observation
	// covers the whole attempt, success or failure alike.
	start := w.Now()
	cert, err := w.Store.CertificateByID(ctx, certID)
	if errors.Is(err, ErrNotFound) {
		return nil // deleted while queued
	}
	if err != nil {
		return err
	}
	attemptID, err := w.Store.CreateAttempt(ctx, cert.ID)
	if err != nil {
		return err
	}
	bg := context.WithoutCancel(ctx)
	tl := NewTimeline(w.Now, func(steps []Step, log string) {
		sctx, cancel := context.WithTimeout(bg, saveTimeout)
		defer cancel()
		if err := w.Store.SaveAttemptProgress(sctx, nil, attemptID, steps, log); err != nil {
			w.Log.Warn("save attempt progress", "attempt", attemptID, "err", err)
		}
	})
	// A panic anywhere below (a bug in this worker or a challenge provider)
	// must not leave the attempt row stuck "running" forever, or the
	// certificate stuck without a backoff scheduling its next attempt: river's
	// own executor recovers a panicking Work call and applies its own retry
	// policy, but nothing else closes out the row we already created or
	// advances the certificate's failure_count/next_renew_at. Record it as a
	// normal failure (same backoff as any other error) here, then re-panic so
	// river's contract (its own logging, error handler and retry/backoff)
	// still applies.
	defer func() {
		if r := recover(); r != nil {
			tl.Logf("panic: %v\n%s", r, truncatedStack())
			// Effective{} here (not the eff run assigns below): a panic never
			// carries an ACME error type, so fail's failed-validation write
			// never triggers regardless, and eff is only otherwise used for
			// that.
			if ferr := w.fail(bg, cert, attemptID, tl, Effective{}, fmt.Errorf("panic: %v", r), start); ferr != nil {
				w.Log.Error("finish attempt after panic", "attempt", attemptID, "err", ferr)
			}
			panic(r)
		}
	}()
	iss, eff, err := w.run(ctx, cert, attemptID, tl)
	if err != nil {
		return w.fail(bg, cert, attemptID, tl, eff, err, start)
	}
	if err := w.succeed(bg, cert, attemptID, tl, iss, eff, start); err != nil {
		// succeed's own transaction rolled back, so the attempt row is still
		// "running"; best-effort finish it as failed instead of leaving it
		// stuck until FailStaleAttempts eventually catches it. This is an
		// infrastructure error (DB), so the certificate row itself (status,
		// failure_count, next_renew_at) is left untouched: river retries the
		// job, and a successful retry needs no backoff to undo.
		tl.Logf("error: %v", err)
		steps, log := tl.Snapshot()
		if ferr := w.Store.FinishAttempt(bg, nil, attemptID, OutcomeFailed, "", nil, steps, log); ferr != nil {
			w.Log.Warn("finish attempt after succeed error", "attempt", attemptID, "err", ferr)
		}
		return err
	}
	return nil
}

func (w *IssueWorker) run(ctx context.Context, cert Certificate, attemptID uuid.UUID, tl *Timeline) (*signer.Issued, Effective, error) {
	eff, err := w.Store.EffectiveFor(ctx, cert)
	if err != nil {
		return nil, eff, err
	}
	if eff.CAID.Value == nil {
		return nil, eff, errors.New("no CA configured: set one on the certificate or in issuance defaults")
	}
	ca, err := w.Store.GetCA(ctx, cert.OrgID, *eff.CAID.Value)
	if err != nil {
		return nil, eff, fmt.Errorf("CA %s: %w", *eff.CAID.Value, err)
	}
	sig, err := w.NewSigner(ctx, ca)
	if err != nil {
		return nil, eff, fmt.Errorf("CA %s: %w", ca.Name, err)
	}

	// A private CA (localca, vaultpki) has no ACME account, publishes no
	// caaIdentities, is not rate-ledger tracked and solves no challenge:
	// runPrivate skips every ACME-only step (Task 9 contract). eff.AccountID
	// being nil is only ever allowed here; the ACME path below still
	// requires one.
	if ca.Private() {
		return w.runPrivate(ctx, cert, ca, sig, eff, tl)
	}
	if eff.AccountID.Value == nil {
		return nil, eff, errors.New("no ACME account configured: set one on the certificate or in issuance defaults")
	}

	cfg, err := w.issuanceSettings(ctx)
	if err != nil {
		return nil, eff, err
	}
	if err := w.caaStep(ctx, tl, cert, ca, eff, sig, cfg); err != nil {
		return nil, eff, err
	}
	if err := w.rateLedgerStep(ctx, tl, cert, ca, cfg); err != nil {
		return nil, eff, err
	}

	tl.Step("account", challenge.StepRunning, "")
	acct, material, err := w.Store.AccountMaterial(ctx, cert.OrgID, *eff.AccountID.Value)
	if err != nil {
		return nil, eff, fmt.Errorf("ACME account %s: %w", *eff.AccountID.Value, err)
	}
	if acct.CAID != ca.ID {
		return nil, eff, fmt.Errorf("ACME account %s belongs to a different CA than %s", acct.Email, ca.Name)
	}
	tl.Step("account", challenge.StepSuccess, acct.Email+" at "+ca.Name)

	router, manual, err := w.buildRouter(ctx, cert, eff, ca, attemptID, tl)
	if err != nil {
		return nil, eff, err
	}
	replaces := w.replacesCert(ctx, cert, eff, ca, tl)
	req := signer.IssueRequest{Names: cert.Names(), KeyType: eff.KeyType.Value, PreferredChain: eff.PreferredChain.Value,
		MustStaple: eff.MustStaple.Value, Account: material, Challenge: router, Replaces: replaces,
		ReuseKeyPKCS8: w.reuseKeyPKCS8(ctx, cert, eff, tl)}
	// Recorded here, directly before the order is actually sent: everything
	// above (account lookup, CA-mismatch check, router/solver build) can
	// still fail the attempt without ever contacting the CA, and none of
	// those must count as an order (fix round 1).
	if err := w.Store.RecordNewOrder(ctx, ca.ID, w.Now()); err != nil {
		return nil, eff, err
	}
	tl.Step("order", challenge.StepRunning, strings.Join(req.Names, ", "))
	iss, err := sig.Issue(ctx, req)
	if err != nil {
		// PreCheck reports readiness (true, nil) to lego even after a
		// manual-dns timeout, so lego proceeds to ask the CA to validate,
		// and a real CA then fails that validation for the masked reason:
		// the CA's own error (unauthorized, usually) is what Issue returns
		// here, not the timeout. Outcome only returns non-nil once WaitReady
		// has actually run and failed, so this can't misfire when the
		// failure was unrelated to manual-dns (or there was no manual-dns
		// rule at all). Joining keeps both the CA's error and the real
		// reason behind it in the recorded error and in errors.As reach.
		if manual != nil {
			if mErr := manual.Outcome(); errors.Is(mErr, challenge.ErrManualTimeout) {
				err = errors.Join(mErr, err)
			}
		}
		return nil, eff, err
	}
	if iss == nil {
		return nil, eff, fmt.Errorf("signer %s returned no certificate and no error", ca.Name)
	}
	tl.Finish(challenge.StepSuccess, "")
	tl.Step("finalize", challenge.StepSuccess, "serial "+iss.Serial)
	return iss, eff, nil
}

// runPrivate issues cert against a private CA (Task 9 contract): account,
// caa, rate_ledger and a "challenge <name>" step per name are all recorded
// StepSkipped "not used by private CAs" — no ACME account is looked up, no
// CAA identities are checked, nothing is rate-ledger tracked and no
// challenge is solved. AccountMaterial, buildRouter, RecordNewOrder and
// replacesCert (ARI-only) are never called; the CSR is built the same way
// (reuseKeyPKCS8 included) and validity is capped by the signer's own
// maxLeafDays/ttl, not here. Only the order step and sig.Issue itself run
// before the shared succeed path.
func (w *IssueWorker) runPrivate(ctx context.Context, cert Certificate, ca CA, sig signer.Signer, eff Effective, tl *Timeline) (*signer.Issued, Effective, error) {
	tl.Step("account", challenge.StepSkipped, "not used by private CAs")
	tl.Step("caa", challenge.StepSkipped, "not used by private CAs")
	tl.Step("rate_ledger", challenge.StepSkipped, "not used by private CAs")
	for _, name := range cert.Names() {
		tl.Step("challenge "+name, challenge.StepSkipped, "not used by private CAs")
	}

	req := signer.IssueRequest{Names: cert.Names(), KeyType: eff.KeyType.Value, PreferredChain: eff.PreferredChain.Value,
		MustStaple: eff.MustStaple.Value, ReuseKeyPKCS8: w.reuseKeyPKCS8(ctx, cert, eff, tl)}
	tl.Step("order", challenge.StepRunning, strings.Join(req.Names, ", "))
	iss, err := sig.Issue(ctx, req)
	if err != nil {
		return nil, eff, err
	}
	if iss == nil {
		return nil, eff, fmt.Errorf("signer %s returned no certificate and no error", ca.Name)
	}
	tl.Finish(challenge.StepSuccess, "")
	tl.Step("finalize", challenge.StepSuccess, "serial "+iss.Serial)
	return iss, eff, nil
}

// reuseKeyPKCS8 returns the current version's stored private key when
// eff.ReuseKey asks for it and its key type still matches, else nil (a
// fresh key is generated); shared by the ACME and private-CA paths.
func (w *IssueWorker) reuseKeyPKCS8(ctx context.Context, cert Certificate, eff Effective, tl *Timeline) []byte {
	if !eff.ReuseKey.Value || cert.CurrentVersionID == nil {
		return nil
	}
	key, kt, err := w.Certs.PrivateKey(ctx, cert.ID, *cert.CurrentVersionID)
	switch {
	case err == nil && kt == string(eff.KeyType.Value):
		return key
	case err == nil:
		tl.Logf("reuseKey requested but the stored key is %s, not %s; generating a fresh key", kt, eff.KeyType.Value)
	default:
		tl.Logf("reuseKey requested but the stored key could not be read (%v); generating a fresh key", err)
	}
	return nil
}

// issuanceSettings loads the global "issuance" section through w.Settings,
// falling back to the built-in defaults (CAA checking on) when Settings is
// nil — production always sets it (see cmd/certforge/serve.go); tests that
// don't care about it may leave it unset.
func (w *IssueWorker) issuanceSettings(ctx context.Context) (IssuanceSettings, error) {
	if w.Settings == nil {
		return defaultIssuanceSettings(), nil
	}
	return w.Settings(ctx)
}

// caaStep runs the CAA pre-check for cert's names before any order, and
// records step "caa" with the outcome:
//   - cfg.CAACheck false: skipped, "disabled in settings".
//   - sig does not implement signer.DirectoryInfo (a CA kind with nothing to
//     check, Phase 5): success, "CA does not publish caaIdentities".
//   - the ACME directory could not be fetched: success (the CA still checks
//     CAA itself during the real order).
//   - the directory publishes no caaIdentities: success, the Deviations R6
//     text ("CA publishes no caaIdentities; CAA not evaluated").
//   - otherwise CheckCAA decides; a forbidding result ends the attempt by
//     returning its *signer.Error, which the caller reports via fail.
func (w *IssueWorker) caaStep(ctx context.Context, tl *Timeline, cert Certificate, ca CA, eff Effective, sig signer.Signer, cfg IssuanceSettings) error {
	if !cfg.CAACheck {
		tl.Step("caa", challenge.StepSkipped, "disabled in settings")
		return nil
	}
	tl.Step("caa", challenge.StepRunning, "")
	di, ok := sig.(signer.DirectoryInfo)
	if !ok {
		tl.Step("caa", challenge.StepSuccess, "CA does not publish caaIdentities")
		return nil
	}
	identities, err := di.CAAIdentities(ctx)
	if err != nil {
		tl.Step("caa", challenge.StepSuccess, fmt.Sprintf("CA directory unreachable (%v); CAA not evaluated", err))
		return nil
	}
	if len(identities) == 0 {
		tl.Step("caa", challenge.StepSuccess, "CA publishes no caaIdentities; CAA not evaluated")
		return nil
	}
	resolvers := eff.Resolvers.Value
	if len(resolvers) == 0 {
		resolvers = ca.Resolvers
	}
	r := w.CAA
	if r == nil {
		r = DNSCAAResolver{}
	}
	detail, err := CheckCAA(ctx, r, cert.Names(), identities, resolvers)
	if err != nil {
		tl.Step("caa", challenge.StepFailed, err.Error())
		return err
	}
	tl.Step("caa", challenge.StepSuccess, detail)
	return nil
}

// validationFailureTypes are the ACME error types recorded against
// failedValidationsPerHour (Deviations R7): a challenge that the CA itself
// rejected, not an infrastructure or configuration error.
var validationFailureTypes = map[string]bool{
	"urn:ietf:params:acme:error:unauthorized":      true,
	"urn:ietf:params:acme:error:dns":               true,
	"urn:ietf:params:acme:error:connection":        true,
	"urn:ietf:params:acme:error:incorrectResponse": true,
	"urn:ietf:params:acme:error:tls":               true,
	"urn:ietf:params:acme:error:caa":               true,
}

// rateLedgerStep runs the local rate-limit check (R7) for cert's names
// against ca's CA-wide ledger. A staging preset is never enforced (its CA
// does not itself rate-limit; Deviations R7) — the check is skipped, but
// its new_order row is still recorded like any other CA's, directly before
// sig.Issue (fix round 1: recording it here, before the account lookup,
// the CA-mismatch check and the solver build, counted orders that were
// never actually sent whenever one of those failed first).
func (w *IssueWorker) rateLedgerStep(ctx context.Context, tl *Timeline, cert Certificate, ca CA, cfg IssuanceSettings) error {
	tl.Step("rate_ledger", challenge.StepRunning, "")
	if !ca.Staging() {
		exceeded, err := CheckLedger(ctx, w.Store, ca.ID, cert.Names(), cfg.RateLimits, w.Now())
		if err != nil {
			return err
		}
		if exceeded != nil {
			tl.Step("rate_ledger", challenge.StepFailed, exceeded.Error())
			return &signer.Error{Type: "urn:ietf:params:acme:error:rateLimited", Detail: exceeded.Error(), Err: exceeded}
		}
		tl.Step("rate_ledger", challenge.StepSuccess, "within limits")
		return nil
	}
	tl.Step("rate_ledger", challenge.StepSuccess, "recorded only (staging CA)")
	return nil
}

// replacesEligible reports whether v (cert's current version) qualifies as
// the certificate signer.IssueRequest.Replaces names for this attempt (Task
// 12, RFC 9773 §5): useAri is set, and v was actually issued (not imported
// or uploaded) by the very CA (caID) this attempt is going to — an
// imported/uploaded version, or one issued against a different CA, has
// nothing this CA would recognise as a ReplacesCertID.
func replacesEligible(useAri bool, v certstore.Version, caID uuid.UUID) bool {
	return useAri && v.Source == "issued" && v.CAID != nil && *v.CAID == caID
}

// replacesCert resolves signer.IssueRequest.Replaces: cert's current
// version's leaf, when replacesEligible, else nil. acme.obtainRequest turns
// a non-nil result into ReplacesCertID (certificate.MakeARICertID); lego's
// own Orders.New already strips replaces and retries when the CA answers
// alreadyReplaced (acme/api/order.go), so nothing here needs its own retry.
//
// useAri is checked first (fix round 1), before any store call: a
// certificate that has not opted into ARI never pays for the extra
// Certs.Get/Material round trip. Once useAri is on, Replaces is only ever
// an optional hint — a failure reading the stored version, its material, or
// parsing its leaf must not fail the whole renewal over it, so any such
// error is logged to the attempt timeline and Replaces is simply omitted.
func (w *IssueWorker) replacesCert(ctx context.Context, cert Certificate, eff Effective, ca CA, tl *Timeline) *x509.Certificate {
	if !eff.RenewPolicy.Value.UseARI || cert.CurrentVersionID == nil {
		return nil
	}
	v, err := w.Certs.Get(ctx, cert.ID, *cert.CurrentVersionID)
	if err != nil {
		tl.Logf("ari replaces: could not read the current version (%v); issuing without it", err)
		return nil
	}
	if !replacesEligible(eff.RenewPolicy.Value.UseARI, v, ca.ID) {
		return nil
	}
	m, err := w.Certs.Material(ctx, cert.ID, *cert.CurrentVersionID, false)
	if err != nil {
		tl.Logf("ari replaces: could not read the current version's material (%v); issuing without it", err)
		return nil
	}
	leaf, err := x509.ParseCertificate(m.LeafDER)
	if err != nil {
		tl.Logf("ari replaces: could not parse the current version's leaf (%v); issuing without it", err)
		return nil
	}
	return leaf
}

// agentProvider builds the relay ChallengeProvider for a rule served by an
// agent (http-01 via: agent, or tls-alpn-01, always agent-served); a nil
// Relay is reported the same way a missing HTTPTokens store is for server
// http-01. Rule ownership and capability were already checked when the
// rule was written (issuance.Store.validateRuleClientTx); a rejection here
// (client deleted or gone offline since) is wrapped with the rule's match
// for the attempt log.
func (w *IssueWorker) agentProvider(ctx context.Context, orgID uuid.UUID, sp challenge.RuleSpec) (challenge.ChallengeProvider, error) {
	if w.Relay == nil {
		return nil, fmt.Errorf("rule %q: agent challenge relay is not configured", sp.Match)
	}
	p, err := w.Relay.Provider(ctx, orgID, *sp.ClientID, sp.Method, sp.Webroot)
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", sp.Match, err)
	}
	return p, nil
}

// buildRouter also returns the ManualProvider used for manual-dns rules (nil
// when none), so run can consult its non-blocking Outcome after a failed
// Issue call and recover the real reason behind a masked manual-dns timeout.
func (w *IssueWorker) buildRouter(ctx context.Context, cert Certificate, eff Effective, ca CA, attemptID uuid.UUID, tl *Timeline) (*challenge.Router, *challenge.ManualProvider, error) {
	specs := append(append([]challenge.RuleSpec{}, cert.Rules...), eff.VerificationRules.Value...)
	type built struct {
		p    challenge.ChallengeProvider
		name string
	}
	cache := map[uuid.UUID]built{}
	var manual *challenge.ManualProvider
	rules := make([]challenge.Rule, 0, len(specs))
	for _, sp := range specs {
		if err := sp.Validate(); err != nil {
			return nil, nil, err
		}
		m, _ := challenge.ParseMatch(sp.Match)
		var p challenge.ChallengeProvider
		label := sp.Match + " → " + string(sp.Method)
		switch sp.Method {
		case challenge.MethodManualDNS:
			if manual == nil {
				manual = challenge.NewManual(w.Store, attemptID, cert.ID)
				if w.ManualWait > 0 {
					manual.Wait = w.ManualWait
				}
				if w.ManualPoll > 0 {
					manual.Poll = w.ManualPoll
				}
			}
			p = manual
		case challenge.MethodHTTP01:
			if sp.EffectiveVia() != challenge.ViaServer {
				cp, err := w.agentProvider(ctx, cert.OrgID, sp)
				if err != nil {
					return nil, nil, err
				}
				p, label = cp, sp.Match+" → http-01 (agent)"
				break
			}
			if w.HTTPTokens == nil {
				return nil, nil, fmt.Errorf("rule %q: server http-01 is not configured", sp.Match)
			}
			p = challenge.NewServerHTTP01(w.HTTPTokens)
			label = sp.Match + " → http-01 (server)"
		case challenge.MethodTLSALPN01:
			// tls-alpn-01 is always served by an agent.
			cp, err := w.agentProvider(ctx, cert.OrgID, sp)
			if err != nil {
				return nil, nil, err
			}
			p, label = cp, sp.Match+" → tls-alpn-01 (agent)"
		default: // dns-01
			id := *sp.DNSCredentialID
			b, ok := cache[id]
			if !ok {
				cred, cfg, err := w.Store.DNSCredentialConfig(ctx, cert.OrgID, id)
				if err != nil {
					return nil, nil, fmt.Errorf("rule %q: DNS credential %s: %w", sp.Match, id, err)
				}
				lp, err := w.BuildDNS(cred.ProviderCode, cfg)
				if err != nil {
					return nil, nil, fmt.Errorf("rule %q: credential %s: %w", sp.Match, cred.Name, err)
				}
				b = built{p: challenge.WrapLego(cred.ProviderCode, lp, cfg), name: cred.Name}
				cache[id] = b
			}
			p, label = b.p, sp.Match+" → "+b.name
		}
		secs := eff.PropagationSeconds.Value
		if sp.PropagationSeconds != nil {
			secs = *sp.PropagationSeconds
		}
		resolvers := sp.Resolvers
		if len(resolvers) == 0 {
			resolvers = eff.Resolvers.Value
		}
		if len(resolvers) == 0 {
			resolvers = ca.Resolvers
		}
		rules = append(rules, challenge.Rule{Matcher: m, Provider: p, Resolvers: resolvers,
			Timeout: time.Duration(secs) * time.Second, AliasZone: sp.CNAMEAliasZone, Label: label})
	}
	r := challenge.NewRouter(ctx, cert.Names(), rules, tl)
	return r, manual, r.Validate()
}

func (w *IssueWorker) succeed(ctx context.Context, cert Certificate, attemptID uuid.UUID, tl *Timeline, iss *signer.Issued, eff Effective, start time.Time) error {
	tx, err := w.Store.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after commit
	// Any Timeline save triggered below (tl.Step/tl.Logf) must not go
	// through the store's own connection pool while this transaction holds a
	// row lock on issuance_attempts: a pool-based UPDATE of the same row
	// would block on that lock and, with a small pool, can deadlock outright
	// (the pool's only connection is the one tx is holding). Route it
	// through tx instead for the rest of this function.
	restore := tl.SetSave(func(steps []Step, log string) {
		sctx, cancel := context.WithTimeout(ctx, saveTimeout)
		defer cancel()
		if err := w.Store.SaveAttemptProgress(sctx, tx, attemptID, steps, log); err != nil {
			w.Log.Warn("save attempt progress", "attempt", attemptID, "err", err)
		}
	})
	defer restore()
	v, err := w.Certs.Insert(ctx, tx, cert.ID, iss, string(eff.KeyType.Value), certstore.InsertOpts{Source: "issued", CAID: eff.CAID.Value})
	if err != nil {
		return err
	}
	if err := w.Store.RecordCertIssued(ctx, tx, *eff.CAID.Value, cert.ID, cert.Names(), w.Now()); err != nil {
		return err
	}
	next := NextRenewAt(eff.RenewPolicy.Value, iss.NotBefore, iss.NotAfter, w.Now())
	// The names this attempt actually issued for are cert.Names() as it was
	// captured at the start of the attempt (run's req.Names); comparing them
	// against the row's current common_name/sans in the same UPDATE detects
	// an operator having changed them while this attempt was in flight — see
	// MarkCertificateIssued.
	actualNext, err := w.Store.q.WithTx(tx).MarkCertificateIssued(ctx, sqlcgen.MarkCertificateIssuedParams{
		ID: cert.ID, CurrentVersionID: &v.ID, IssuedCommonName: cert.CommonName, IssuedSans: cert.SANs, NextRenewAt: next})
	if err != nil {
		return err
	}
	if actualNext != nil && !actualNext.Equal(next) {
		tl.Logf("names changed while this attempt was running; scheduling an immediate reissue at %s instead of the normal renewal date %s",
			actualNext.UTC().Format(time.RFC3339), next.UTC().Format(time.RFC3339))
		next = *actualNext
	}
	tl.Step("store", challenge.StepSuccess, "version "+v.ID.String())
	tl.Logf("issued serial %s valid until %s; next renewal %s", iss.Serial, iss.NotAfter.UTC().Format(time.RFC3339), next.UTC().Format(time.RFC3339))
	steps, log := tl.Snapshot()
	if err := w.Store.FinishAttempt(ctx, tx, attemptID, OutcomeSuccess, "", nil, steps, log); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	metrics.IssuanceAttempts.WithLabelValues("success").Inc()
	metrics.IssuanceDuration.Observe(w.Now().Sub(start).Seconds())
	w.notifyVersion(ctx, cert.ID, v.ID)
	polled := cert
	polled.CurrentVersionID, polled.NextRenewAt, polled.FailureCount = &v.ID, &next, 0
	w.pollARIBestEffort(ctx, polled, attemptID)
	return nil
}

// pollARIBestEffort polls the ACME Renewal Information window for the
// version succeed just committed (Task 12), right after that commit: a
// failure (including a CA that does not support ARI at all, the common
// case today) never turns an issuance that already committed into a
// failure. It is logged to the server log and, since the attempt itself
// already finished and committed by the time this runs (so the failure
// cannot be folded into the timeline snapshot FinishAttempt already
// wrote), appended as its own line to the attempt's log (fix round 1: the
// brief requires it there, not only in the server log). A single ad-hoc
// call needs no cross-certificate signer cache, hence nil.
// cert.CurrentVersionID/NextRenewAt/FailureCount already reflect what
// succeed just wrote (not the stale values read at the start of this
// attempt); pollOne itself re-checks managed/useAri and is a no-op when
// either does not apply.
func (w *IssueWorker) pollARIBestEffort(ctx context.Context, cert Certificate, attemptID uuid.UUID) {
	if w.ARI == nil {
		return
	}
	if err := w.ARI.pollOne(ctx, cert, nil); err != nil {
		w.Log.Warn("ari poll after issuance", "attempt", attemptID, "certificate", cert.ID, "err", err)
		if lerr := w.Store.AppendAttemptLog(ctx, attemptID, fmt.Sprintf("ari poll: %v", err)); lerr != nil {
			w.Log.Warn("append ari poll error to attempt log", "attempt", attemptID, "err", lerr)
		}
	}
}

// notifyVersion calls every listener; a panicking listener is logged and
// never stops the others or the worker.
func (w *IssueWorker) notifyVersion(ctx context.Context, certID, versionID uuid.UUID) {
	for _, l := range w.Listeners {
		func() {
			defer func() {
				if r := recover(); r != nil {
					w.Log.Error("version listener panicked", "cert", certID, "version", versionID, "panic", r)
				}
			}()
			l.OnVersion(ctx, certID, versionID)
		}()
	}
}

// fail records cause as this attempt's outcome and schedules the next one.
// eff is the Effective resolved by run (zero-valued from the panic-recovery
// path, which never carries an ACME error type): when it names a CA, cause's
// ACME type is one of validationFailureTypes, and se.Status is non-zero (the
// CA actually returned it — a local pre-check like caa's own, never sent to
// the CA, reports no HTTP status at all, fix round 1), a failed_validation
// row is recorded against it (Deviations R7) — best-effort, logged rather
// than failing the whole attempt-finish on a write error.
func (w *IssueWorker) fail(ctx context.Context, cert Certificate, attemptID uuid.UUID, tl *Timeline, eff Effective, cause error, start time.Time) error {
	now := w.Now()
	failures := cert.FailureCount + 1
	var acmeType string
	var retryAfter time.Duration
	var se *signer.Error
	if errors.As(cause, &se) {
		acmeType, retryAfter = se.Type, se.RetryAfter
	}
	if caID := eff.CAID.Value; caID != nil && se != nil && se.Status != 0 && validationFailureTypes[acmeType] {
		if rerr := w.Store.RecordFailedValidation(ctx, *caID, cert.ID, cert.Names(), now); rerr != nil {
			w.Log.Warn("record failed validation", "attempt", attemptID, "err", rerr)
		}
	}
	// A rate-ledger failure (LedgerExceeded, wrapped in se above) schedules
	// next_renew_at at the window's expiry rather than the usual exponential
	// backoff — a longer backoff would often outlast the window pointlessly,
	// a shorter one would just fail again — but a later CA Retry-After (rare
	// here: the ledger check never contacts the CA) still wins.
	var le *LedgerExceeded
	var next time.Time
	if errors.As(cause, &le) {
		next = le.RetryAt
		if alt := now.Add(retryAfter); alt.After(next) {
			next = alt
		}
	} else {
		next = now.Add(Backoff(failures, retryAfter, w.Rand))
	}
	tl.Finish(challenge.StepFailed, cause.Error())
	tl.Logf("error: %v", cause)
	tl.Logf("failure %d; next attempt at %s (in %s)", failures, next.UTC().Format(time.RFC3339), next.Sub(now).Round(time.Second))
	steps, log := tl.Snapshot()
	var ra *time.Time
	switch {
	case le != nil:
		ra = &next
	case retryAfter > 0:
		t := now.Add(retryAfter)
		ra = &t
	}
	if err := w.Store.FinishAttempt(ctx, nil, attemptID, OutcomeFailed, acmeType, ra, steps, log); err != nil {
		return err
	}
	status := StatusFailed
	if cert.CurrentVersionID != nil && cert.Status == StatusActive {
		status = StatusActive // a valid version is still deployed
	}
	if cert.Status == StatusExpired {
		status = StatusExpired // stay expired; failed would flap against MarkExpired
	}
	if err := w.Store.MarkFailed(ctx, cert.ID, status, failures, cause.Error(), next); err != nil {
		return err
	}
	// cert.NextRenewAt is updated to the value MarkFailed just wrote (the
	// struct fail received reflects the certificate as it was before this
	// failure) so a listener's FailureInfo-adjacent nextAttemptAt detail is
	// accurate, not stale.
	cert.NextRenewAt = &next
	metrics.IssuanceAttempts.WithLabelValues("failed").Inc()
	metrics.IssuanceDuration.Observe(w.Now().Sub(start).Seconds())
	w.notifyFailure(ctx, cert, failures, ClassifyFailure(lastFailedStep(steps), cause))
	return nil
}

// notifyFailure calls OnFailure, panic-safe like notifyVersion: a
// panicking listener is logged and never turns an already-committed
// failure into a returned error.
func (w *IssueWorker) notifyFailure(ctx context.Context, cert Certificate, failures int, f FailureInfo) {
	if w.OnFailure == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			w.Log.Error("failure listener panicked", "cert", cert.ID, "panic", r)
		}
	}()
	w.OnFailure.OnFailure(ctx, cert, failures, f)
}
