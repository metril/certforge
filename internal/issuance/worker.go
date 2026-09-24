package issuance

import (
	"context"
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
	"github.com/metril/certforge/internal/signer"
	acmesigner "github.com/metril/certforge/internal/signer/acme"
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

// IssueWorker runs one issuance attempt. ACME and challenge failures are
// recorded on the attempt and scheduled via next_renew_at; only
// infrastructure errors (database) are returned for river to retry.
type IssueWorker struct {
	river.WorkerDefaults[IssueArgs]
	Store      *Store
	Certs      *certstore.Store
	NewSigner  func(CA) signer.Signer
	BuildDNS   func(code string, cfg map[string]string) (legochallenge.Provider, error)
	Now        func() time.Time
	Rand       func() float64
	ManualWait time.Duration // 0 = challenge.DefaultManualWait
	ManualPoll time.Duration // 0 = 2s
	Log        *slog.Logger
}

// NewIssueWorker wires production defaults.
func NewIssueWorker(store *Store, certs *certstore.Store) *IssueWorker {
	return &IssueWorker{Store: store, Certs: certs, NewSigner: DefaultSigner, BuildDNS: challenge.Build,
		Now: time.Now, Rand: rand.Float64, Log: slog.Default()}
}

// DefaultSigner builds the lego-backed ACME signer for ca.
func DefaultSigner(ca CA) signer.Signer {
	return acmesigner.New(acmesigner.Config{DirectoryURL: ca.DirectoryURL, TrustBundlePEM: ca.TrustBundlePEM})
}

// Timeout covers a manual-dns wait plus propagation and finalisation.
func (w *IssueWorker) Timeout(*river.Job[IssueArgs]) time.Duration { return 3 * time.Hour }

// Work implements river.Worker.
func (w *IssueWorker) Work(ctx context.Context, job *river.Job[IssueArgs]) error {
	return w.Issue(ctx, job.Args.CertID)
}

// Issue performs one attempt for certID.
func (w *IssueWorker) Issue(ctx context.Context, certID uuid.UUID) error {
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
		if err := w.Store.SaveAttemptProgress(bg, attemptID, steps, log); err != nil {
			w.Log.Warn("save attempt progress", "attempt", attemptID, "err", err)
		}
	})
	// A panic anywhere below (a bug in this worker or a challenge provider)
	// must not leave the attempt row stuck "running" forever: river's own
	// executor recovers a panicking Work call and applies its own retry
	// policy, but nothing else closes out the row we already created. Record
	// it as failed here, then re-panic so river's contract (its own logging,
	// error handler and retry/backoff) still applies.
	defer func() {
		if r := recover(); r != nil {
			tl.Finish(challenge.StepFailed, fmt.Sprintf("panic: %v", r))
			tl.Logf("panic: %v\n%s", r, debug.Stack())
			steps, log := tl.Snapshot()
			if ferr := w.Store.FinishAttempt(bg, nil, attemptID, OutcomeFailed, "", nil, steps, log); ferr != nil {
				w.Log.Error("finish attempt after panic", "attempt", attemptID, "err", ferr)
			}
			panic(r)
		}
	}()
	tl.Step("caa", challenge.StepSkipped, "CAA pre-check arrives in Phase 4")
	tl.Step("rate_ledger", challenge.StepSkipped, "rate-limit ledger arrives in Phase 4")

	iss, eff, err := w.run(ctx, cert, attemptID, tl)
	if err != nil {
		return w.fail(bg, cert, attemptID, tl, err)
	}
	if err := w.succeed(bg, cert, attemptID, tl, iss, eff); err != nil {
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
	tl.Step("account", challenge.StepRunning, "")
	eff, err := w.Store.EffectiveFor(ctx, cert)
	if err != nil {
		return nil, eff, err
	}
	if eff.CAID.Value == nil || eff.AccountID.Value == nil {
		return nil, eff, errors.New("no CA or ACME account configured: set them on the certificate or in issuance defaults")
	}
	ca, err := w.Store.GetCA(ctx, cert.OrgID, *eff.CAID.Value)
	if err != nil {
		return nil, eff, fmt.Errorf("CA %s: %w", *eff.CAID.Value, err)
	}
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
	req := signer.IssueRequest{Names: cert.Names(), KeyType: eff.KeyType.Value, PreferredChain: eff.PreferredChain.Value,
		MustStaple: eff.MustStaple.Value, Account: material, Challenge: router}
	if eff.ReuseKey.Value && cert.CurrentVersionID != nil {
		key, kt, err := w.Certs.PrivateKey(ctx, cert.ID, *cert.CurrentVersionID)
		switch {
		case err == nil && kt == string(eff.KeyType.Value):
			req.ReuseKeyPKCS8 = key
		case err == nil:
			tl.Logf("reuseKey requested but the stored key is %s, not %s; generating a fresh key", kt, eff.KeyType.Value)
		default:
			tl.Logf("reuseKey requested but the stored key could not be read (%v); generating a fresh key", err)
		}
	}
	tl.Step("order", challenge.StepRunning, strings.Join(req.Names, ", "))
	iss, err := w.NewSigner(ca).Issue(ctx, req)
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
		if sp.Method == challenge.MethodManualDNS {
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
		} else {
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
				b = built{p: challenge.WrapLego(cred.ProviderCode, lp), name: cred.Name}
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

func (w *IssueWorker) succeed(ctx context.Context, cert Certificate, attemptID uuid.UUID, tl *Timeline, iss *signer.Issued, eff Effective) error {
	tx, err := w.Store.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after commit
	v, err := w.Certs.Insert(ctx, tx, cert.ID, iss, string(eff.KeyType.Value))
	if err != nil {
		return err
	}
	next := NextRenewAt(eff.RenewPolicy.Value, iss.NotBefore, iss.NotAfter, w.Now())
	if err := w.Store.q.WithTx(tx).MarkCertificateIssued(ctx, sqlcgen.MarkCertificateIssuedParams{
		ID: cert.ID, CurrentVersionID: &v.ID, NextRenewAt: &next}); err != nil {
		return err
	}
	tl.Step("store", challenge.StepSuccess, "version "+v.ID.String())
	tl.Logf("issued serial %s valid until %s; next renewal %s", iss.Serial, iss.NotAfter.UTC().Format(time.RFC3339), next.UTC().Format(time.RFC3339))
	steps, log := tl.Snapshot()
	if err := w.Store.FinishAttempt(ctx, tx, attemptID, OutcomeSuccess, "", nil, steps, log); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (w *IssueWorker) fail(ctx context.Context, cert Certificate, attemptID uuid.UUID, tl *Timeline, cause error) error {
	now := w.Now()
	failures := cert.FailureCount + 1
	var acmeType string
	var retryAfter time.Duration
	var se *signer.Error
	if errors.As(cause, &se) {
		acmeType, retryAfter = se.Type, se.RetryAfter
	}
	delay := Backoff(failures, retryAfter, w.Rand)
	next := now.Add(delay)
	tl.Finish(challenge.StepFailed, cause.Error())
	tl.Logf("error: %v", cause)
	tl.Logf("failure %d; next attempt at %s (in %s)", failures, next.UTC().Format(time.RFC3339), delay.Round(time.Second))
	steps, log := tl.Snapshot()
	var ra *time.Time
	if retryAfter > 0 {
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
	return w.Store.MarkFailed(ctx, cert.ID, status, failures, cause.Error(), next)
}
