//go:build integration

package issuance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/signer"
)

// TestPrivateCASkipsACMESteps (Task 9): a certificate whose effective CA is
// a private (localca) CA issues through the ordinary IssueWorker.Issue path
// with account, caa, rate_ledger and its one challenge step all recorded
// StepSkipped "not used by private CAs" — the router, the ACME account
// lookup and the rate ledger's new_order recording never run. The org
// defaults' own ACME account (inherited, not set on this certificate) is
// silently dropped rather than rejected (EffectiveFor's private-CA rule).
func TestPrivateCASkipsACMESteps(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ca, err := f.store.CreateCA(ctx, f.org, CAInput{Name: "Local Root", Type: CATypeLocalCA,
		Config: map[string]any{"subject": map[string]any{"commonName": "Test Root"}}})
	if err != nil {
		t.Fatal(err)
	}
	// Seed an org accountId (f.ca/f.acct, both ACME — valid on their own)
	// explicitly, so this certificate's own accountId override to a
	// private CA inherits a real, non-nil account to drop: the doc
	// comment's "inherited account dropped" claim is otherwise never
	// actually exercised (runPrivate ignores AccountID regardless of its
	// value, so nothing here would fail if the account were not dropped).
	if err := f.store.PutOrgDefaults(ctx, f.org, Defaults{CAID: &f.ca.ID, AccountID: &f.acct.ID}); err != nil {
		t.Fatal(err)
	}
	c, err := f.store.CreateCertificate(ctx, f.org, CertInput{Name: "priv", CommonName: "priv.example.test",
		Overrides: Defaults{CAID: &ca.ID}})
	if err != nil {
		t.Fatal(err)
	}
	eff, err := f.store.EffectiveFor(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if eff.AccountID.Value != nil {
		t.Fatalf("effective accountId = %v, want dropped (nil): the org default (%s) belongs to an ACME CA, not this certificate's private one", *eff.AccountID.Value, f.acct.ID)
	}

	certs := certstore.New(f.pool, cryptotest.PrefixBox{})
	w := NewIssueWorker(f.store, certs)
	w.Now = func() time.Time { return now0 }
	w.Rand = func() float64 { return 0.5 }
	w.NewSigner = (&SignerFactory{Store: f.store, BaseURL: func(context.Context) string { return "" }}).New

	if err := w.Issue(ctx, c.ID); err != nil {
		t.Fatal(err)
	}

	got, err := f.store.GetCertificate(ctx, f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusActive || got.CurrentVersionID == nil {
		t.Fatalf("cert = %+v", got)
	}
	a := lastAttempt(t, f, c.ID)
	st := stepStatus(a)
	for name, want := range map[string]string{"account": challenge.StepSkipped, "caa": challenge.StepSkipped,
		"rate_ledger": challenge.StepSkipped, "challenge priv.example.test": challenge.StepSkipped,
		"order": challenge.StepSuccess, "finalize": challenge.StepSuccess} {
		if st[name] != want {
			t.Errorf("step %s = %q want %q (%v)", name, st[name], want, st)
		}
	}
	for _, s := range a.Steps {
		switch s.Name {
		case "account", "caa", "rate_ledger", "challenge priv.example.test":
			if s.Message != "not used by private CAs" {
				t.Errorf("step %s message = %q, want %q", s.Name, s.Message, "not used by private CAs")
			}
		}
	}
	if a.Outcome != OutcomeSuccess {
		t.Fatalf("attempt = %+v", a)
	}
}

// TestACMEStepsUnchanged (Task 9): the private-CA gate added to run() must
// leave an ACME issuance's step list byte-identical to 4A — every classic
// step still runs and succeeds, and none of them (account, caa, rate_ledger)
// is ever recorded StepSkipped for an acme CA.
func TestACMEStepsUnchanged(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"acme-unchanged.example.test"},
		[]challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	fs := &fakeSigner{issued: issuedFor(t, c.Names(), now0)}
	if err := newWorker(f, fs).Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	a := lastAttempt(t, f, c.ID)
	st := stepStatus(a)
	want := map[string]string{"caa": challenge.StepSuccess, "rate_ledger": challenge.StepSuccess, "account": challenge.StepSuccess,
		"order": challenge.StepSuccess, "challenge acme-unchanged.example.test": challenge.StepSuccess,
		"finalize": challenge.StepSuccess, "store": challenge.StepSuccess}
	for name, wantStatus := range want {
		if st[name] != wantStatus {
			t.Errorf("step %s = %q want %q (%v) — ACME step list must stay byte-identical to 4A", name, st[name], wantStatus, st)
		}
	}
	if len(st) != len(want) {
		t.Errorf("step count = %d, want %d (no extra/skipped steps introduced by the private-CA gate): %v", len(st), len(want), st)
	}
}

// TestARISkipsPrivate (Task 9): the ARI poll worker skips a certificate
// whose current version was issued by a private CA — no RenewalInfo call is
// ever made (a private signer has none to give), both right after issuance
// (IssueWorker.succeed's own best-effort poll) and from the periodic
// ARIPollWorker path; the window and next_renew_at are left untouched, and
// only ari_retry_after is bumped so the certificate does not occupy every
// subsequent poll's page.
func TestARISkipsPrivate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ca, err := f.store.CreateCA(ctx, f.org, CAInput{Name: "Local Root", Type: CATypeLocalCA,
		Config: map[string]any{"subject": map[string]any{"commonName": "Test Root"}}})
	if err != nil {
		t.Fatal(err)
	}
	useAri := RenewPolicy{Mode: RenewPercent, Value: 33, UseARI: true}
	c, err := f.store.CreateCertificate(ctx, f.org, CertInput{Name: "priv-ari", CommonName: "priv-ari.example.test",
		Overrides: Defaults{CAID: &ca.ID, RenewPolicy: &useAri}})
	if err != nil {
		t.Fatal(err)
	}

	certs := certstore.New(f.pool, cryptotest.PrefixBox{})
	ari := NewARIPollWorker(f.store, certs)
	ari.Now = func() time.Time { return now0 }
	ari.NewSigner = func(context.Context, CA) (signer.Signer, error) {
		t.Fatal("RenewalInfo must not be requested for a private CA")
		return nil, nil
	}

	w := NewIssueWorker(f.store, certs)
	w.Now = func() time.Time { return now0 }
	w.Rand = func() float64 { return 0.5 }
	w.NewSigner = (&SignerFactory{Store: f.store, BaseURL: func(context.Context) string { return "" }}).New
	w.ARI = ari
	if err := w.Issue(ctx, c.ID); err != nil {
		t.Fatal(err)
	}

	got, err := f.store.GetCertificate(ctx, f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AriWindowStart != nil {
		t.Fatalf("post-issuance ARI poll wrote a window for a private CA: %+v", got)
	}

	// The periodic poll path (pollOne, called directly the way PollDue would).
	if err := ari.pollOne(ctx, got, map[uuid.UUID]signer.Signer{}); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.GetCertificate(ctx, f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.AriWindowStart != nil {
		t.Fatalf("window written for a private CA: %+v", after)
	}
	if after.AriRetryAfter == nil {
		t.Fatal("ari_retry_after was not bumped")
	}
}
