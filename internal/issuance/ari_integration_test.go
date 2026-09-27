//go:build integration

package issuance

import (
	"context"
	"crypto/x509"
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
	if err := aw.pollOne(context.Background(), got); err != nil {
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
	if err := aw.pollOne(context.Background(), got); err != nil {
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
	if err := aw.pollOne(context.Background(), got); err != nil {
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
	if err := aw.pollOne(context.Background(), got); err != nil {
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
	if err := aw.pollOne(context.Background(), unmanaged); err != nil {
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
