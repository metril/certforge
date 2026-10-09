//go:build integration

package issuance

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	legochallenge "github.com/go-acme/lego/v4/challenge"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/signer"
)

type nopDNS struct{}

func (nopDNS) Present(string, string, string) error { return nil }
func (nopDNS) CleanUp(string, string, string) error { return nil }

// fakeSigner drives the solver the way lego does: Present for every name,
// then PreCheck, then returns issued or err.
type fakeSigner struct {
	mu     sync.Mutex
	calls  int
	issued *signer.Issued
	err    error
}

func (f *fakeSigner) Kind() string { return "fake" }
func (f *fakeSigner) Issue(_ context.Context, req signer.IssueRequest) (*signer.Issued, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	for _, n := range req.Names {
		d := strings.TrimPrefix(n, "*.")
		if err := req.Challenge.Present(d, "tok", "ka-"+n); err != nil {
			return nil, err
		}
	}
	for _, n := range req.Names {
		d := strings.TrimPrefix(n, "*.")
		ok, err := req.Challenge.PreCheck(n, "_acme-challenge."+d+".", "v", func(string, string) (bool, error) { return true, nil })
		if err != nil || !ok {
			return nil, fmt.Errorf("propagation %s: %w", n, err)
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	if f.issued == nil {
		// A well-behaved CA never hands back a certificate with no error:
		// PreCheck reports readiness (true, nil) even after a masked
		// manual-dns timeout, so this is what a real CA's own validation
		// failure looks like once lego asks it to finalize the order.
		return nil, &signer.Error{Type: "urn:ietf:params:acme:error:unauthorized", Status: 403,
			Detail: "one or more domain validations failed"}
	}
	return f.issued, nil
}
func (f *fakeSigner) Revoke(context.Context, *x509.Certificate, int) error { return nil }
func (f *fakeSigner) RenewalInfo(context.Context, *x509.Certificate) (*signer.Window, error) {
	return nil, nil
}

// renamingSigner wraps fakeSigner and, once Issue's challenge solving
// succeeds, changes the certificate's names in the store before returning —
// simulating an operator editing SANs while this attempt is still in
// flight, after the names it is issuing for (req.Names, captured at the
// start of the attempt) were already fixed.
type renamingSigner struct {
	fakeSigner
	f       *fixture
	certID  uuid.UUID
	newSANs []string
}

func (s *renamingSigner) Issue(ctx context.Context, req signer.IssueRequest) (*signer.Issued, error) {
	iss, err := s.fakeSigner.Issue(ctx, req)
	if err != nil {
		return nil, err
	}
	cur, err := s.f.store.GetCertificate(ctx, s.f.org, s.certID)
	if err != nil {
		return nil, err
	}
	if _, _, err := s.f.store.UpdateCertificate(ctx, s.f.org, s.certID,
		CertInput{Name: cur.Name, CommonName: cur.CommonName, SANs: s.newSANs, Rules: cur.Rules}, nil); err != nil {
		return nil, err
	}
	return iss, nil
}

// panicSigner simulates a worker/provider bug: Issue panics instead of
// returning an error.
type panicSigner struct{}

func (panicSigner) Kind() string { return "panic" }
func (panicSigner) Issue(context.Context, signer.IssueRequest) (*signer.Issued, error) {
	panic("simulated signer panic")
}
func (panicSigner) Revoke(context.Context, *x509.Certificate, int) error { return nil }
func (panicSigner) RenewalInfo(context.Context, *x509.Certificate) (*signer.Window, error) {
	return nil, nil
}

var now0 = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

func newWorker(f *fixture, fs *fakeSigner) *IssueWorker {
	w := NewIssueWorker(f.store, certstore.New(f.pool, cryptotest.PrefixBox{}))
	w.NewSigner = func(context.Context, CA) (signer.Signer, error) { return fs, nil }
	w.BuildDNS = func(string, map[string]string) (legochallenge.Provider, error) { return nopDNS{}, nil }
	w.Now = func() time.Time { return now0 }
	w.Rand = func() float64 { return 0.5 }
	return w
}

func (f *fixture) cert(t *testing.T, names []string, rules []challenge.RuleSpec) Certificate {
	t.Helper()
	c, err := f.store.CreateCertificate(context.Background(), f.org, CertInput{Name: names[0], CommonName: names[0], SANs: names[1:], Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func lastAttempt(t *testing.T, f *fixture, certID uuid.UUID) Attempt {
	t.Helper()
	as, err := f.store.ListAttempts(context.Background(), f.org, certID, 1, true)
	if err != nil || len(as) != 1 {
		t.Fatalf("attempts = %v %v", as, err)
	}
	return as[0]
}

func stepStatus(a Attempt) map[string]string {
	m := map[string]string{}
	for _, s := range a.Steps {
		m[s.Name] = s.Status
	}
	return m
}

func TestIssueSuccess(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"example.test", "*.example.test"}, []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	// Seed a prior failure so success is shown to reset failure_count to 0,
	// not merely leave an already-zero count alone.
	if err := f.store.MarkFailed(context.Background(), c.ID, StatusFailed, 2, "boom", now0); err != nil {
		t.Fatal(err)
	}
	fs := &fakeSigner{issued: issuedFor(t, c.Names(), now0)}
	if err := newWorker(f, fs).Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if got.Status != StatusActive || got.CurrentVersionID == nil || got.FailureCount != 0 {
		t.Fatalf("cert = %+v", got)
	}
	wantNext := NextRenewAt(RenewPolicy{Mode: RenewPercent, Value: 33}, now0, now0.Add(90*24*time.Hour), now0)
	if !got.NextRenewAt.Equal(wantNext) {
		t.Fatalf("next = %v want %v", got.NextRenewAt, wantNext)
	}
	a := lastAttempt(t, f, c.ID)
	st := stepStatus(a)
	// caa is "success" (not "skipped"): fakeSigner does not implement
	// signer.DirectoryInfo, so the step succeeds with "CA does not publish
	// caaIdentities" — see Task 10. rate_ledger is "success" too, Task 11:
	// the fixture's CA is preset "custom" (not staging) with no prior
	// ledger rows, so it is enforced and within every limit.
	for name, want := range map[string]string{"caa": "success", "rate_ledger": "success", "account": "success", "order": "success",
		"challenge example.test": "success", "finalize": "success", "store": "success"} {
		if st[name] != want {
			t.Errorf("step %s = %q want %q (%v)", name, st[name], want, st)
		}
	}
	if a.Outcome != OutcomeSuccess || a.FinishedAt == nil {
		t.Fatalf("attempt = %+v", a)
	}
}

// Review Focus: name matching no rule and no catch-all.
func TestIssueUncoveredNameFailsBeforeOrder(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"example.test", "lab.other.test"}, []challenge.RuleSpec{{Match: "example.test", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	fs := &fakeSigner{}
	if err := newWorker(f, fs).Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if fs.calls != 0 {
		t.Fatal("CA must not be contacted")
	}
	got, _ := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if got.Status != StatusFailed || got.FailureCount != 1 || !strings.Contains(got.LastError, "no verification rule matches lab.other.test") {
		t.Fatalf("cert = %+v", got)
	}
	if d := got.NextRenewAt.Sub(now0); d != 5*time.Minute {
		t.Fatalf("backoff = %v", d)
	}
	if a := lastAttempt(t, f, c.ID); a.Outcome != OutcomeFailed {
		t.Fatalf("attempt = %+v", a)
	}
}

// Review Focus: CA answers 429 with Retry-After.
func TestIssueRateLimitedHonoursRetryAfter(t *testing.T) {
	f := newFixture(t)
	c := f.cert(t, []string{"example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: ptr(f.credential(t, "cf"))}})
	fs := &fakeSigner{err: &signer.Error{Type: "urn:ietf:params:acme:error:rateLimited", Status: 429, RetryAfter: 3 * time.Hour, Err: errors.New("too many new orders")}}
	if err := newWorker(f, fs).Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if d := got.NextRenewAt.Sub(now0); d != 3*time.Hour {
		t.Fatalf("next retry in %v, want 3h", d)
	}
	a := lastAttempt(t, f, c.ID)
	if a.ACMEErrorType != "urn:ietf:params:acme:error:rateLimited" || a.RetryAfter == nil || !a.RetryAfter.Equal(now0.Add(3*time.Hour)) {
		t.Fatalf("attempt = %+v", a)
	}
}

// caaSigner adds signer.DirectoryInfo to fakeSigner, the way the real ACME
// signer does, so a certificate's CAA step can be driven through the whole
// worker.
type caaSigner struct {
	fakeSigner
	identities []string
}

func (s *caaSigner) CAAIdentities(context.Context) ([]string, error) { return s.identities, nil }

// TestIssueCAAForbidsBeforeOrder: review fix round 1 for Task 10.
// TestWorkerCAAStep's old "forbidden" subtest called caaStep directly, so
// its assertion that signer.Issue was never called proved nothing (the
// test itself never called Issue either). This drives a forbidding CAA
// record through the real Issue path — the attempt fails, the caa step is
// recorded failed with the caa ACME error type, and the signer's Issue is
// genuinely never invoked (fs.calls stays 0), proven by fakeSigner's own
// call counter across the whole worker, not by trusting a narrower call.
func TestIssueCAAForbidsBeforeOrder(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	fs := &caaSigner{identities: []string{"letsencrypt.org"}}
	w := newWorker(f, &fs.fakeSigner)
	w.NewSigner = func(context.Context, CA) (signer.Signer, error) { return fs, nil }
	w.CAA = fakeCAAResolver{records: map[string][]CAARecord{
		"example.test": {{Tag: "issue", Value: "other-ca.example"}},
	}}

	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if fs.calls != 0 {
		t.Fatalf("signer.Issue was called %d time(s)", fs.calls)
	}
	got, _ := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if got.Status != StatusFailed {
		t.Fatalf("cert status = %s, want %s", got.Status, StatusFailed)
	}
	a := lastAttempt(t, f, c.ID)
	if a.Outcome != OutcomeFailed || a.ACMEErrorType != "urn:ietf:params:acme:error:caa" {
		t.Fatalf("attempt = %+v", a)
	}
	if st := stepStatus(a)["caa"]; st != challenge.StepFailed {
		t.Fatalf("caa step = %q, want %q", st, challenge.StepFailed)
	}
}

// Review Focus: manual-dns timeout while the operator is away. Against a real
// CA, PreCheck's masking means Issue fails with the CA's own validation
// error (here fakeSigner's unauthorized signer.Error), not the timeout
// directly; the recorded error must still surface the real reason (the
// manual-dns timeout) via errors.Join, and the attempt must still record the
// CA's ACME error type.
func TestIssueManualTimeout(t *testing.T) {
	f := newFixture(t)
	c := f.cert(t, []string{"lab.example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodManualDNS}})
	w := newWorker(f, &fakeSigner{})
	w.Now = time.Now
	w.ManualWait, w.ManualPoll = 100*time.Millisecond, 10*time.Millisecond
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if !strings.Contains(got.LastError, "not confirmed in time") || got.FailureCount != 1 {
		t.Fatalf("cert = %+v", got)
	}
	if recs, _ := f.store.ManualPending(context.Background(), f.org, c.ID); len(recs) != 0 {
		t.Fatalf("pending records left behind: %v", recs)
	}
	if st := stepStatus(lastAttempt(t, f, c.ID)); st["challenge lab.example.test"] != "failed" {
		t.Fatalf("steps = %v", st)
	}
	a := lastAttempt(t, f, c.ID)
	if a.ACMEErrorType != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("attempt = %+v", a)
	}
}

// Review Focus: a panic anywhere in the attempt (a worker or provider bug)
// must not leave the attempt row stuck "running" forever for river to keep
// retrying against a fresh CA order; Issue must record it as failed and
// re-panic so river's own panic handling still applies.
func TestIssuePanicRecordsFailedAttempt(t *testing.T) {
	f := newFixture(t)
	c := f.cert(t, []string{"example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: ptr(f.credential(t, "cf"))}})
	w := newWorker(f, &fakeSigner{})
	w.NewSigner = func(context.Context, CA) (signer.Signer, error) { return panicSigner{}, nil }
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Issue did not re-panic")
			}
		}()
		_ = w.Issue(context.Background(), c.ID)
		t.Fatal("unreachable: Issue should have panicked")
	}()
	a := lastAttempt(t, f, c.ID)
	if a.Outcome != OutcomeFailed || a.FinishedAt == nil {
		t.Fatalf("attempt = %+v", a)
	}
	if !strings.Contains(a.Log, "panic") || !strings.Contains(a.Log, "simulated signer panic") {
		t.Fatalf("log missing panic detail: %q", a.Log)
	}
	// Fix wave item 5: the panic-recovery path must apply the same backoff
	// as a normal failure, not just record the attempt and leave the
	// certificate's failure_count/next_renew_at untouched.
	got, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusFailed || got.FailureCount != 1 || !strings.Contains(got.LastError, "simulated signer panic") {
		t.Fatalf("cert = %+v", got)
	}
	if d := got.NextRenewAt.Sub(now0); d != 5*time.Minute {
		t.Fatalf("backoff = %v, want the normal first-failure backoff", d)
	}
}

// Fix wave item 1: an operator changing a certificate's names while an
// issuance is in flight enqueues its own reissue (UpdateCertificate's
// reissue=true sets next_renew_at=now()), but that enqueue is deduplicated
// against the job already running for the old names (IssueArgs.InsertOpts).
// So when that in-flight attempt then succeeds for the old names, it must
// not push next_renew_at out to the normal renewal date — losing the edit
// for the certificate's whole lifetime — but keep it due now, so the
// scheduler picks the new names back up within its next sweep.
func TestIssueKeepsImmediateRenewalWhenNamesChangeDuringAttempt(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	fs := &renamingSigner{fakeSigner: fakeSigner{issued: issuedFor(t, c.Names(), now0)}, f: f, certID: c.ID, newSANs: []string{"extra.example.test"}}
	w := newWorker(f, &fs.fakeSigner)
	w.NewSigner = func(context.Context, CA) (signer.Signer, error) { return fs, nil }
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	got, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusActive || got.CurrentVersionID == nil {
		t.Fatalf("cert = %+v", got)
	}
	if got.NextRenewAt == nil || got.NextRenewAt.After(time.Now().Add(2*time.Second)) {
		t.Fatalf("next_renew_at = %v, want at or just after now (names changed mid-attempt)", got.NextRenewAt)
	}
}

// Fix wave item 3: with no propagationSeconds configured at any level (the
// built-in default is now the "provider default" sentinel), the router's
// rule timeout falls back to the DNS provider's own Timeout() — letting a
// credential's own *_PROPAGATION_TIMEOUT config take effect instead of
// always being shadowed by a fixed built-in value.
type timeoutCapturingSigner struct {
	fakeSigner
	gotTimeout time.Duration
}

func (f *timeoutCapturingSigner) Issue(ctx context.Context, req signer.IssueRequest) (*signer.Issued, error) {
	f.gotTimeout, _ = req.Challenge.Timeout()
	return f.fakeSigner.Issue(ctx, req)
}

// slowDNS is a lego provider whose own Timeout() reports a distinctive
// value, standing in for a credential's own *_PROPAGATION_TIMEOUT config.
type slowDNS struct{ nopDNS }

func (slowDNS) Timeout() (time.Duration, time.Duration) { return 42 * time.Second, 5 * time.Second }

func TestIssuePropagationDefaultsToProviderTimeout(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	fs := &timeoutCapturingSigner{fakeSigner: fakeSigner{issued: issuedFor(t, c.Names(), now0)}}
	w := newWorker(f, &fs.fakeSigner)
	w.NewSigner = func(context.Context, CA) (signer.Signer, error) { return fs, nil }
	w.BuildDNS = func(string, map[string]string) (legochallenge.Provider, error) { return slowDNS{}, nil }
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if fs.gotTimeout != 42*time.Second {
		t.Fatalf("router timeout = %v, want the provider's 42s (no propagationSeconds configured anywhere)", fs.gotTimeout)
	}
}

func TestIssueManualConfirm(t *testing.T) {
	f := newFixture(t)
	c := f.cert(t, []string{"lab.example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodManualDNS}})
	w := newWorker(f, &fakeSigner{issued: issuedFor(t, []string{"lab.example.test"}, now0)})
	w.Now = time.Now
	w.ManualPoll = 10 * time.Millisecond
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			recs, _ := f.store.ManualPending(context.Background(), f.org, c.ID)
			if len(recs) == 1 {
				if recs[0].Name != "_acme-challenge.lab.example.test" {
					t.Errorf("record name = %s", recs[0].Name)
				}
				_, _ = f.store.ConfirmManual(context.Background(), f.org, c.ID)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	<-done // the goroutine still calls t.Errorf; it must finish before the test does
	if got, _ := f.store.GetCertificate(context.Background(), f.org, c.ID); got.Status != StatusActive {
		t.Fatalf("cert = %+v", got)
	}
}

// TestWorkerLedgerBlocksAndSchedules: 5 prior cert_issued rows for the same
// exact name set already reach a duplicateCertsPerWeek limit of 5, so this
// attempt must fail at the rate_ledger step before ever contacting the CA,
// and next_renew_at must be exactly the window's expiry (the oldest of the
// 5 rows plus 7 days), not the usual exponential backoff.
func TestWorkerLedgerBlocksAndSchedules(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	names := []string{"dup.example.test"}
	c := f.cert(t, names, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: ptr(f.credential(t, "cf"))}})
	oldest := now0.Add(-5 * time.Hour)
	for i := 5; i >= 1; i-- {
		if err := f.store.RecordCertIssued(ctx, nil, f.ca.ID, c.ID, names, now0.Add(-time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	fs := &fakeSigner{issued: issuedFor(t, names, now0)}
	w := newWorker(f, fs)
	w.Settings = func(context.Context) (IssuanceSettings, error) {
		return IssuanceSettings{RateLimits: RateLimits{DuplicateCertsPerWeek: 5}}, nil
	}
	if err := w.Issue(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if fs.calls != 0 {
		t.Fatalf("signer.Issue was called %d time(s)", fs.calls)
	}
	got, err := f.store.GetCertificate(ctx, f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantRetry := oldest.Add(7 * 24 * time.Hour)
	if got.Status != StatusFailed || got.NextRenewAt == nil || !got.NextRenewAt.Equal(wantRetry) {
		t.Fatalf("cert = %+v, want next_renew_at %s", got, wantRetry)
	}
	a := lastAttempt(t, f, c.ID)
	if a.Outcome != OutcomeFailed || a.ACMEErrorType != "urn:ietf:params:acme:error:rateLimited" {
		t.Fatalf("attempt = %+v", a)
	}
	if st := stepStatus(a)["rate_ledger"]; st != challenge.StepFailed {
		t.Fatalf("rate_ledger step = %q", st)
	}
}

// TestWorkerNewOrderNotRecordedBeforeAccountLookup: fix round 1. new_order
// must be recorded directly before sig.Issue, not by the rate_ledger step.
// This certificate overrides only caId to a second CA, inheriting the
// fixture org's default accountId — which belongs to the *first* CA — so
// run's own CA-mismatch check ("ACME account ... belongs to a different
// CA") fires right after the account lookup succeeds, well after
// rate_ledger but well before any order is attempted; that must leave no
// new_order row behind.
func TestWorkerNewOrderNotRecordedBeforeAccountLookup(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	ca2, err := f.store.CreateCA(ctx, f.org, CAInput{Name: "Other CA", Preset: "custom", DirectoryURL: "https://other.test/dir", Resolvers: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"badaccount.example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	cur, err := f.store.GetCertificate(ctx, f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.UpdateCertificate(ctx, f.org, c.ID, CertInput{Name: cur.Name, CommonName: cur.CommonName, SANs: cur.SANs,
		Rules: cur.Rules, Overrides: Defaults{CAID: &ca2.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	fs := &fakeSigner{}
	if err := newWorker(f, fs).Issue(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if fs.calls != 0 {
		t.Fatalf("signer.Issue was called %d time(s)", fs.calls)
	}
	got, err := f.store.GetCertificate(ctx, f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusFailed || !strings.Contains(got.LastError, "different CA") {
		t.Fatalf("cert = %+v, want a CA-mismatch failure", got)
	}
	// The effective CA for this attempt was ca2, not the fixture's f.ca:
	// f.ledgerCount only ever looks at f.ca's rows, so it would misreport
	// zero regardless of where new_order landed. Count ca2's own rows.
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rate_ledger WHERE ca_id = $1 AND kind = $2`, ca2.ID, kindNewOrder).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("new_order rows = %d, want 0 (the CA-mismatch check failed before any order was attempted)", n)
	}
}

// TestFailDoesNotRecordFailedValidationForLocalCAAForbid: fix round 1
// (controller ruling). The caa step's own local pre-check never contacts
// the CA (signer.Error.Status stays 0), so its failure must not count
// against failedValidationsPerHour — that limit tracks failures the CA
// itself saw.
func TestFailDoesNotRecordFailedValidationForLocalCAAForbid(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"caa-fail.example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	fs := &caaSigner{identities: []string{"letsencrypt.org"}}
	w := newWorker(f, &fs.fakeSigner)
	w.NewSigner = func(context.Context, CA) (signer.Signer, error) { return fs, nil }
	w.CAA = fakeCAAResolver{records: map[string][]CAARecord{
		"caa-fail.example.test": {{Tag: "issue", Value: "other-ca.example"}},
	}}
	if err := w.Issue(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	a := lastAttempt(t, f, c.ID)
	if st := stepStatus(a)["caa"]; st != challenge.StepFailed {
		t.Fatalf("caa step = %q, want failed", st)
	}
	if n := f.ledgerCount(t, kindFailedValidation); n != 0 {
		t.Fatalf("failed_validation rows = %d, want 0 (a local CAA pre-check never reached the CA)", n)
	}
}

func TestIssueSuccessNotifiesListeners(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"notify.example.test"}, []challenge.RuleSpec{{Match: "notify.example.test", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	w := newWorker(f, &fakeSigner{issued: issuedFor(t, c.Names(), now0)})
	rec := &recordingListener{}
	w.Listeners = []VersionListener{rec}
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if len(rec.got) != 1 || rec.got[0][0] != c.ID || got.CurrentVersionID == nil || rec.got[0][1] != *got.CurrentVersionID {
		t.Fatalf("listener got %v, current %v", rec.got, got.CurrentVersionID)
	}
}

// replacesCapturingSigner captures IssueRequest.Replaces for
// TestWorkerSetsReplaces (fix round 1: replacesEligible was unit-tested in
// isolation in worker_test.go, but run()'s actual wiring of req.Replaces
// through the whole worker had no coverage of its own).
type replacesCapturingSigner struct {
	fakeSigner
	got *x509.Certificate
}

func (s *replacesCapturingSigner) Issue(ctx context.Context, req signer.IssueRequest) (*signer.Issued, error) {
	s.got = req.Replaces
	return s.fakeSigner.Issue(ctx, req)
}

// TestWorkerSetsReplaces: set only for a renewal (not the first issuance),
// against the same CA the current version was actually issued by, with
// useAri on.
func TestWorkerSetsReplaces(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	useAri := RenewPolicy{Mode: RenewPercent, Value: 33, UseARI: true}
	c, err := f.store.CreateCertificate(context.Background(), f.org, CertInput{
		Name: "replaces-test", CommonName: "replaces-test.example.test",
		Rules:     []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}},
		Overrides: Defaults{RenewPolicy: &useAri},
	})
	if err != nil {
		t.Fatal(err)
	}

	// First issuance: no current version yet, so Replaces must be nil even
	// with useAri on.
	first := issuedFor(t, c.Names(), now0)
	fs1 := &replacesCapturingSigner{fakeSigner: fakeSigner{issued: first}}
	w := newWorker(f, &fs1.fakeSigner)
	w.NewSigner = func(context.Context, CA) (signer.Signer, error) { return fs1, nil }
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if fs1.got != nil {
		t.Fatalf("first issuance: Replaces = %v, want nil (no prior version)", fs1.got)
	}

	// Renewal against the same CA: Replaces is the first version's leaf.
	fs2 := &replacesCapturingSigner{fakeSigner: fakeSigner{issued: issuedFor(t, c.Names(), now0.Add(time.Hour))}}
	w.NewSigner = func(context.Context, CA) (signer.Signer, error) { return fs2, nil }
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	firstLeaf, err := x509.ParseCertificate(first.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	if fs2.got == nil || fs2.got.SerialNumber.Cmp(firstLeaf.SerialNumber) != 0 {
		t.Fatalf("renewal: Replaces = %v, want the first version's leaf (serial %v)", fs2.got, firstLeaf.SerialNumber)
	}

	// A renewal against a different CA must not set Replaces.
	otherCA, err := f.store.CreateCA(context.Background(), f.org, CAInput{Name: "Other CA", Preset: "custom", DirectoryURL: "https://other.test/dir", Resolvers: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	otherAcct := f.account(t, otherCA.ID)
	cur, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.UpdateCertificate(context.Background(), f.org, c.ID, CertInput{
		Name: cur.Name, CommonName: cur.CommonName, SANs: cur.SANs, Rules: cur.Rules,
		Overrides: Defaults{RenewPolicy: &useAri, CAID: &otherCA.ID, AccountID: &otherAcct},
	}, nil); err != nil {
		t.Fatal(err)
	}
	fs3 := &replacesCapturingSigner{fakeSigner: fakeSigner{issued: issuedFor(t, c.Names(), now0.Add(2*time.Hour))}}
	w.NewSigner = func(context.Context, CA) (signer.Signer, error) { return fs3, nil }
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if fs3.got != nil {
		t.Fatalf("different CA: Replaces = %v, want nil", fs3.got)
	}
}

// erroringRenewalInfoSigner errors on every RenewalInfo call, standing in
// for a CA the ARI poll cannot reach.
type erroringRenewalInfoSigner struct {
	fakeSigner
}

func (*erroringRenewalInfoSigner) RenewalInfo(context.Context, *x509.Certificate) (*signer.Window, error) {
	return nil, errors.New("ari boom")
}

// TestSucceedAppendsARIPollErrorToAttemptLog is fix round 1's review
// finding: a post-issuance ARI poll failure used to go only to the server
// log; the brief requires it in the attempt's own log too.
func TestSucceedAppendsARIPollErrorToAttemptLog(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	useAri := RenewPolicy{Mode: RenewPercent, Value: 33, UseARI: true}
	c, err := f.store.CreateCertificate(context.Background(), f.org, CertInput{
		Name: "ari-log-test", CommonName: "ari-log-test.example.test",
		Rules:     []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}},
		Overrides: Defaults{RenewPolicy: &useAri},
	})
	if err != nil {
		t.Fatal(err)
	}
	fs := &erroringRenewalInfoSigner{fakeSigner: fakeSigner{issued: issuedFor(t, c.Names(), now0)}}
	w := newWorker(f, &fs.fakeSigner)

	ari := NewARIPollWorker(f.store, certstore.New(f.pool, cryptotest.PrefixBox{}))
	ari.NewSigner = func(context.Context, CA) (signer.Signer, error) { return fs, nil }
	ari.Now = func() time.Time { return now0 }
	ari.Rand = func() float64 { return 0.5 }
	w.ARI = ari

	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	a := lastAttempt(t, f, c.ID)
	if a.Outcome != OutcomeSuccess {
		t.Fatalf("outcome = %v, want success (an ARI poll failure must not fail an already-committed issuance)", a.Outcome)
	}
	if !strings.Contains(a.Log, "ari boom") {
		t.Fatalf("attempt log = %q, want it to mention the ari poll error", a.Log)
	}
}

// revokingSigner revokes the cert's current version mid-attempt (as a
// revoke request landing while DNS propagation is in flight) and then
// returns the issued material.
type revokingSigner struct {
	fakeSigner
	pool   *pgxpool.Pool
	certID uuid.UUID
}

func (r *revokingSigner) Issue(ctx context.Context, req signer.IssueRequest) (*signer.Issued, error) {
	iss, err := r.fakeSigner.Issue(ctx, req)
	if err != nil {
		return nil, err
	}
	if _, err := r.pool.Exec(ctx, `UPDATE certificate_versions SET revoked_at = now() WHERE cert_id = $1`, r.certID); err != nil {
		return nil, err
	}
	return iss, nil
}

// A key revoked mid-attempt must not leave the new version scheduled for a
// normal renewal: succeed keeps the version but makes the cert due now.
func TestSucceedRenewsNowWhenKeyRevokedMidAttempt(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	c, err := f.store.CreateCertificate(context.Background(), f.org, CertInput{
		Name: "revoke-mid", CommonName: "revoke-mid.example.test",
		Rules: []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}},
	})
	if err != nil {
		t.Fatal(err)
	}
	first := issuedFor(t, c.Names(), now0)
	w := newWorker(f, &fakeSigner{issued: first})
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	second := *first
	second.Serial = "02"
	rs := &revokingSigner{fakeSigner: fakeSigner{issued: &second}, pool: f.pool, certID: c.ID}
	w.NewSigner = func(context.Context, CA) (signer.Signer, error) { return rs, nil }
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	var due bool
	if err := f.pool.QueryRow(context.Background(), `SELECT next_renew_at <= now() + interval '1 minute' FROM certificates WHERE id = $1`, c.ID).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if !due {
		t.Fatal("next_renew_at was not reset to now after the key was revoked mid-attempt")
	}
}
