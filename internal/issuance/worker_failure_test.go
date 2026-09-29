//go:build integration

package issuance

import (
	"context"
	"sync"
	"testing"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/signer"
)

// recordingFailureListener records every OnFailure call.
type recordingFailureListener struct {
	mu    sync.Mutex
	calls []FailureInfo
}

func (r *recordingFailureListener) OnFailure(_ context.Context, _ Certificate, _ int, f FailureInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, f)
}

// panicFailureListener always panics.
type panicFailureListener struct{}

func (panicFailureListener) OnFailure(context.Context, Certificate, int, FailureInfo) {
	panic("simulated failure listener panic")
}

// TestFailureListenerPanicSafe: a panicking OnFailure must not turn an
// already-committed attempt failure into a returned error (the same
// contract notifyVersion already gives VersionListener), and the
// certificate/attempt rows must still be recorded exactly as they would be
// with no listener at all.
func TestFailureListenerPanicSafe(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	w := newWorker(f, &fakeSigner{})
	w.OnFailure = panicFailureListener{}

	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	got, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusFailed || got.FailureCount != 1 {
		t.Fatalf("cert = %+v", got)
	}
	a := lastAttempt(t, f, c.ID)
	if a.Outcome != OutcomeFailed {
		t.Fatalf("attempt = %+v", a)
	}
}

// TestOnFailureCalledEveryAttempt: OnFailure fires for every failed
// attempt (the threshold/dedupe decision is the listener's own job, not
// fail's), classified via ClassifyFailure — here the CAA pre-check fails
// before any order is sent, so Step is "caa" and Class is "caa".
func TestOnFailureCalledEveryAttempt(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	fs := &caaSigner{identities: []string{"letsencrypt.org"}}
	w := newWorker(f, &fs.fakeSigner)
	w.NewSigner = func(context.Context, CA) (signer.Signer, error) { return fs, nil }
	w.CAA = fakeCAAResolver{records: map[string][]CAARecord{
		"example.test": {{Tag: "issue", Value: "other-ca.example"}},
	}}
	rec := &recordingFailureListener{}
	w.OnFailure = rec

	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) != 1 {
		t.Fatalf("OnFailure calls = %d, want 1", len(rec.calls))
	}
	if rec.calls[0].Step != "caa" || rec.calls[0].Class != "caa" {
		t.Fatalf("f = %+v", rec.calls[0])
	}
}
