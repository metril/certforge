//go:build integration

package issuance

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/signer"
)

// windowSigner adds a controllable RenewalInfo to fakeSigner, standing in
// for the real ACME signer's CA round trip.
type windowSigner struct {
	fakeSigner
	win *signer.Window
	err error
}

func (s *windowSigner) RenewalInfo(context.Context, *x509.Certificate) (*signer.Window, error) {
	return s.win, s.err
}

func newARIWorker(f *fixture, ws *windowSigner) *ARIPollWorker {
	w := NewARIPollWorker(f.store, certstore.New(f.pool, cryptotest.PrefixBox{}))
	w.NewSigner = func(CA) signer.Signer { return ws }
	w.Now = func() time.Time { return now0 }
	w.Rand = func() float64 { return 0.5 }
	return w
}

// TestARIPollNeverLater covers ari.go's core rule (Task 12): next_renew_at
// only ever moves earlier, never later, and only under the right
// conditions. Task 12 brief's five cases, in order: an earlier window
// lowers next_renew_at; a later one leaves it; ari_retry_after in the
// future skips the certificate; a current_version_id mismatch leaves both
// the window and next_renew_at unchanged; failure_count > 0 leaves
// next_renew_at unchanged (though the window itself still updates).
func TestARIPollNeverLater(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	useAri := RenewPolicy{Mode: RenewPercent, Value: 33, UseARI: true}
	c, err := f.store.CreateCertificate(context.Background(), f.org, CertInput{
		Name: "ari-test", CommonName: "ari-test.example.test",
		Rules:     []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}},
		Overrides: Defaults{RenewPolicy: &useAri},
	})
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeSigner{issued: issuedFor(t, c.Names(), now0)}
	w := newWorker(f, fs)
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	got, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantPolicy := NextRenewAt(useAri, now0, now0.Add(90*24*time.Hour), now0)
	if got.NextRenewAt == nil || !got.NextRenewAt.Equal(wantPolicy) {
		t.Fatalf("next_renew_at after issuance = %v, want %v", got.NextRenewAt, wantPolicy)
	}

	// 1. An earlier window lowers next_renew_at into it.
	earlier := &signer.Window{Start: now0.Add(24 * time.Hour), End: now0.Add(48 * time.Hour)}
	ws := &windowSigner{win: earlier}
	aw := newARIWorker(f, ws)
	if err := aw.pollOne(context.Background(), got, map[uuid.UUID]signer.Signer{}); err != nil {
		t.Fatal(err)
	}
	got, err = f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.NextRenewAt.Before(earlier.Start) || got.NextRenewAt.After(earlier.End) {
		t.Fatalf("next_renew_at = %v, want inside [%v,%v]", got.NextRenewAt, earlier.Start, earlier.End)
	}
	if got.AriWindowStart == nil || !got.AriWindowStart.Equal(earlier.Start) || got.AriWindowEnd == nil || !got.AriWindowEnd.Equal(earlier.End) {
		t.Fatalf("stored window = %v..%v, want %v..%v", got.AriWindowStart, got.AriWindowEnd, earlier.Start, earlier.End)
	}
	if got.AriRetryAfter == nil || !got.AriRetryAfter.Equal(now0.Add(ariDefaultRetryAfter)) {
		t.Fatalf("ari_retry_after = %v, want %v (no RetryAfter on the window)", got.AriRetryAfter, now0.Add(ariDefaultRetryAfter))
	}
	lowered := *got.NextRenewAt

	// 2. A later window (further out than the already-lowered date) leaves
	// next_renew_at where it is; the cached window itself still refreshes.
	later := &signer.Window{Start: now0.Add(80 * 24 * time.Hour), End: now0.Add(85 * 24 * time.Hour)}
	ws.win = later
	if err := aw.pollOne(context.Background(), got, map[uuid.UUID]signer.Signer{}); err != nil {
		t.Fatal(err)
	}
	got, err = f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.NextRenewAt.Equal(lowered) {
		t.Fatalf("a later window moved next_renew_at: got %v, want unchanged %v", got.NextRenewAt, lowered)
	}
	if got.AriWindowStart == nil || !got.AriWindowStart.Equal(later.Start) {
		t.Fatalf("stored window did not refresh: got %v, want start %v", got.AriWindowStart, later.Start)
	}

	// 3. ari_retry_after in the future (set directly here rather than
	// relying on wall-clock drift against the stubbed now0) makes the
	// batch entrypoint skip this certificate entirely.
	if _, err := f.pool.Exec(context.Background(), `UPDATE certificates SET ari_retry_after = $2 WHERE id = $1`,
		c.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ws.win = &signer.Window{Start: now0.Add(time.Minute), End: now0.Add(2 * time.Minute)}
	before, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.PollDue(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.NextRenewAt.Equal(*before.NextRenewAt) || !after.AriWindowStart.Equal(*before.AriWindowStart) {
		t.Fatalf("a future ari_retry_after did not skip the poll: before=%+v after=%+v", before, after)
	}
	// Clear it so the remaining cases (called via pollOne directly, not the
	// batch entrypoint) are unaffected by this subtest.
	if _, err := f.pool.Exec(context.Background(), `UPDATE certificates SET ari_retry_after = NULL WHERE id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	got = after

	// 4. A stale current_version_id (as if a reissue landed between fetching
	// the leaf and writing back) leaves both the window and next_renew_at
	// unchanged.
	stale := uuid.New()
	beforeWindow, beforeNext := *got.AriWindowStart, *got.NextRenewAt
	if err := f.store.SetARIWindow(context.Background(), c.ID, stale, now0.Add(time.Minute), now0.Add(2*time.Minute), now0, now0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.LowerNextRenewAt(context.Background(), c.ID, stale, now0); err != nil {
		t.Fatal(err)
	}
	got, err = f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.AriWindowStart.Equal(beforeWindow) || !got.NextRenewAt.Equal(beforeNext) {
		t.Fatalf("a stale current_version_id was applied: window=%v (want %v) next=%v (want %v)",
			got.AriWindowStart, beforeWindow, got.NextRenewAt, beforeNext)
	}

	// 5. failure_count > 0 leaves next_renew_at unchanged, even for an
	// earlier window; the window itself still updates (it is informational,
	// not gated on failure_count).
	failAt := now0.Add(10 * time.Minute)
	if err := f.store.MarkFailed(context.Background(), c.ID, StatusActive, 1, "boom", failAt); err != nil {
		t.Fatal(err)
	}
	got, err = f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	ws.win = &signer.Window{Start: now0.Add(time.Minute), End: now0.Add(2 * time.Minute)}
	if err := aw.pollOne(context.Background(), got, map[uuid.UUID]signer.Signer{}); err != nil {
		t.Fatal(err)
	}
	got, err = f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.NextRenewAt.Equal(failAt) {
		t.Fatalf("failure_count > 0: next_renew_at = %v, want unchanged %v", got.NextRenewAt, failAt)
	}
	if got.AriWindowStart == nil || !got.AriWindowStart.Equal(ws.win.Start) {
		t.Fatalf("failure_count > 0: window did not still refresh: got %v, want %v", got.AriWindowStart, ws.win.Start)
	}
}

// TestARIPollSkipsUnmanagedAndNoUseAri: pollOne is a no-op (no window
// written) for an unmanaged certificate and for a managed one whose
// effective renewPolicy.useAri is off — the global constraint that an ARI
// window is never applied to an unmanaged certificate, plus the ordinary
// "not opted in" case.
func TestARIPollSkipsUnmanagedAndNoUseAri(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"no-ari.example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	fs := &fakeSigner{issued: issuedFor(t, c.Names(), now0)}
	w := newWorker(f, fs)
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	got, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	ws := &windowSigner{win: &signer.Window{Start: now0, End: now0.Add(time.Hour)}}
	aw := newARIWorker(f, ws)

	// useAri unset (BuiltinDefaults): no-op.
	if err := aw.pollOne(context.Background(), got, map[uuid.UUID]signer.Signer{}); err != nil {
		t.Fatal(err)
	}
	still, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if still.AriWindowStart != nil {
		t.Fatalf("useAri off: window was written: %v", still.AriWindowStart)
	}

	// Managed=false: no-op even when useAri would otherwise be on (the
	// global constraint: an ARI window is never applied to an unmanaged
	// certificate).
	useAri := RenewPolicy{Mode: RenewPercent, Value: 33, UseARI: true}
	unmanaged := still
	unmanaged.Managed = false
	unmanaged.Overrides = Defaults{RenewPolicy: &useAri}
	if err := aw.pollOne(context.Background(), unmanaged, map[uuid.UUID]signer.Signer{}); err != nil {
		t.Fatal(err)
	}
	still, err = f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if still.AriWindowStart != nil {
		t.Fatalf("unmanaged: window was written: %v", still.AriWindowStart)
	}
}

// countingWindowSigner tracks (by leaf serial number) every distinct
// certificate it was asked to poll, and always errors for one designated
// "permanently broken" serial — standing in for a CA call that never
// succeeds for a particular certificate (a bad cached order id, a CA-side
// data problem, etc).
type countingWindowSigner struct {
	fakeSigner
	mu        sync.Mutex
	seen      map[string]bool
	badSerial string
	win       *signer.Window
}

func (s *countingWindowSigner) RenewalInfo(_ context.Context, cert *x509.Certificate) (*signer.Window, error) {
	s.mu.Lock()
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	s.seen[cert.SerialNumber.String()] = true
	s.mu.Unlock()
	if cert.SerialNumber.String() == s.badSerial {
		return nil, errors.New("permanently broken CA call")
	}
	return s.win, nil
}

func (s *countingWindowSigner) seenCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// TestARIPollDuePaginatesPastFirstPage is fix round 1's review finding:
// ListARIDue's old single LIMIT page, combined with a skipped or erroring
// certificate never getting its own ari_retry_after set, meant such a
// certificate (sorted first by id) occupied a page slot on every run
// forever, and anything after the first page was never reached. PollDue
// now walks every due certificate with a keyset cursor in one run, and
// bumps ari_retry_after even when a certificate errors, so five
// certificates over a page size of two (three pages) are every one polled
// in a single PollDue call, the one that always errors still ends up with
// a future ari_retry_after (so it does not occupy a slot on the next run
// either), and an immediate second call re-polls nothing.
func TestARIPollDuePaginatesPastFirstPage(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	useAri := RenewPolicy{Mode: RenewPercent, Value: 33, UseARI: true}
	start := time.Now()
	win := &signer.Window{Start: start.Add(time.Hour).Truncate(time.Microsecond), End: start.Add(2 * time.Hour).Truncate(time.Microsecond)}
	cs := &countingWindowSigner{win: win}

	const n = 5
	const badIndex = 2
	certs := make([]Certificate, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("page-%d.example.test", i)
		c, err := f.store.CreateCertificate(context.Background(), f.org, CertInput{
			Name: name, CommonName: name,
			Rules:     []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}},
			Overrides: Defaults{RenewPolicy: &useAri},
		})
		if err != nil {
			t.Fatal(err)
		}
		iss := issuedFor(t, c.Names(), now0.Add(time.Duration(i)*time.Second))
		w := newWorker(f, &fakeSigner{issued: iss})
		if err := w.Issue(context.Background(), c.ID); err != nil {
			t.Fatal(err)
		}
		got, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		certs[i] = got
		if i == badIndex {
			leaf, err := x509.ParseCertificate(iss.LeafDER)
			if err != nil {
				t.Fatal(err)
			}
			cs.badSerial = leaf.SerialNumber.String()
		}
	}

	aw := NewARIPollWorker(f.store, certstore.New(f.pool, cryptotest.PrefixBox{}))
	aw.NewSigner = func(CA) signer.Signer { return cs }
	aw.Now = time.Now
	aw.Rand = func() float64 { return 0.5 }

	if err := aw.PollDue(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if got := cs.seenCount(); got != n {
		t.Fatalf("RenewalInfo was called for %d of %d certificates, want %d (pagination stopped short)", got, n, n)
	}
	for i, c := range certs {
		got, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		if i == badIndex {
			if got.AriWindowStart != nil {
				t.Fatalf("bad cert: window = %v, want nil (RenewalInfo always errors for it)", got.AriWindowStart)
			}
		} else if got.AriWindowStart == nil || !got.AriWindowStart.Equal(win.Start) {
			t.Fatalf("cert %d: window = %v, want %v", i, got.AriWindowStart, win.Start)
		}
		if got.AriRetryAfter == nil || !got.AriRetryAfter.After(start) {
			t.Fatalf("cert %d: ari_retry_after = %v, want set to an instant after %v (fix round 1: even a skipped/erroring certificate must not stay due forever)", i, got.AriRetryAfter, start)
		}
	}

	// Every certificate's ari_retry_after is now in the future: an
	// immediate second call must not re-poll any of them, including the
	// permanently erroring one.
	if err := aw.PollDue(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if got := cs.seenCount(); got != n {
		t.Fatalf("a second call changed the seen count to %d, want unchanged %d (nothing should be due yet)", got, n)
	}
}

// TestMarkCertificateIssuedClearsStaleARIWindow: fix round 1. A stale ARI
// window from a previous version must not survive a reissue — the API
// would otherwise show a window that has nothing to do with the
// certificate's actual current version until the next poll happens to
// overwrite it, which can be up to 6 hours away.
func TestMarkCertificateIssuedClearsStaleARIWindow(t *testing.T) {
	f := newFixture(t)
	cred := f.credential(t, "cf")
	useAri := RenewPolicy{Mode: RenewPercent, Value: 33, UseARI: true}
	c, err := f.store.CreateCertificate(context.Background(), f.org, CertInput{
		Name: "stale-window", CommonName: "stale-window.example.test",
		Rules:     []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}},
		Overrides: Defaults{RenewPolicy: &useAri},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := newWorker(f, &fakeSigner{issued: issuedFor(t, c.Names(), now0)})
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	got, err := f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Stamp a window as if a poll had already run for this (first) version.
	if err := f.store.SetARIWindow(context.Background(), c.ID, *got.CurrentVersionID,
		now0, now0.Add(time.Hour), now0, now0.Add(ariDefaultRetryAfter)); err != nil {
		t.Fatal(err)
	}
	got, err = f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AriWindowStart == nil {
		t.Fatal("window was not stamped; test setup is broken")
	}

	// Reissue: a second version becomes current.
	w.NewSigner = func(CA) signer.Signer { return &fakeSigner{issued: issuedFor(t, c.Names(), now0.Add(time.Hour))} }
	if err := w.Issue(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}

	got, err = f.store.GetCertificate(context.Background(), f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AriWindowStart != nil || got.AriWindowEnd != nil || got.AriCheckedAt != nil || got.AriRetryAfter != nil {
		t.Fatalf("stale window survived reissue: %+v", got)
	}
}
