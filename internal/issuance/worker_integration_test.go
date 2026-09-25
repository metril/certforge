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
		CertInput{Name: cur.Name, CommonName: cur.CommonName, SANs: s.newSANs, Rules: cur.Rules}); err != nil {
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
	w.NewSigner = func(CA) signer.Signer { return fs }
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
	as, err := f.store.ListAttempts(context.Background(), f.org, certID, 1)
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
	for name, want := range map[string]string{"caa": "skipped", "rate_ledger": "skipped", "account": "success", "order": "success",
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
	w.NewSigner = func(CA) signer.Signer { return panicSigner{} }
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
	w.NewSigner = func(CA) signer.Signer { return fs }
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
	w.NewSigner = func(CA) signer.Signer { return fs }
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
