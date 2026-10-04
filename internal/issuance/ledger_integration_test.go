//go:build integration

package issuance

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/signer"
)

// ledgerCount returns how many of the fixture CA's rate_ledger rows are of
// kind kind.
func (f *fixture) ledgerCount(t *testing.T, kind string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM rate_ledger WHERE ca_id = $1 AND kind = $2`, f.ca.ID, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCheckLedgerWindows(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.cert(t, []string{"example.test"}, nil)
	within := now0.Add(-6 * 24 * time.Hour)  // inside the 7d window
	outside := now0.Add(-8 * 24 * time.Hour) // outside it
	if err := f.store.RecordCertIssued(ctx, nil, f.ca.ID, c.ID, []string{"example.test"}, within); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordCertIssued(ctx, nil, f.ca.ID, c.ID, []string{"example.test"}, outside); err != nil {
		t.Fatal(err)
	}

	limits := RateLimits{CertsPerRegisteredDomainPerWeek: 1}
	exceeded, err := CheckLedger(ctx, f.store, f.ca.ID, []string{"example.test"}, limits, now0)
	if err != nil {
		t.Fatal(err)
	}
	if exceeded == nil {
		t.Fatal("want exceeded")
	}
	wantRetry := within.Add(7 * 24 * time.Hour)
	if exceeded.Limit != LimitCertsPerRegisteredDomainPerWeek || exceeded.Count != 1 || exceeded.Max != 1 || !exceeded.RetryAt.Equal(wantRetry) {
		t.Fatalf("exceeded = %+v, want RetryAt %s", exceeded, wantRetry)
	}

	// max=0 disables the limit.
	if exceeded, err := CheckLedger(ctx, f.store, f.ca.ID, []string{"example.test"}, RateLimits{}, now0); err != nil || exceeded != nil {
		t.Fatalf("exceeded = %+v, err = %v, want nil, nil", exceeded, err)
	}
}

// TestCheckLedgerExcludesExactWindowBoundary: fix round 1 (controller
// ruling). A row exactly window-old (at == now-window) must not count: the
// window's own RetryAt is oldest+window, so a retry exactly at RetryAt must
// see that oldest row have already left, not still count it.
func TestCheckLedgerExcludesExactWindowBoundary(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.cert(t, []string{"boundary.example.test"}, nil)
	boundary := now0.Add(-7 * 24 * time.Hour) // exactly the 7d edge
	if err := f.store.RecordCertIssued(ctx, nil, f.ca.ID, c.ID, []string{"boundary.example.test"}, boundary); err != nil {
		t.Fatal(err)
	}
	exceeded, err := CheckLedger(ctx, f.store, f.ca.ID, []string{"boundary.example.test"}, RateLimits{CertsPerRegisteredDomainPerWeek: 1}, now0)
	if err != nil {
		t.Fatal(err)
	}
	if exceeded != nil {
		t.Fatalf("exceeded = %+v, want nil: a row exactly at the window boundary must not count", exceeded)
	}
}

// TestRateLedgerReportShowsFailingOnlyCertificate: fix round 1 (review
// finding). A certificate that has only ever failed validation (never
// issued) must still surface a failedValidationsPerHour item for its
// domain — failed_validation rows carry no names_hash/duplicate scoping,
// but they do carry cert_id, and domain discovery must consider them.
func TestRateLedgerReportShowsFailingOnlyCertificate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.cert(t, []string{"failsonly.example.test"}, nil)
	if err := f.store.RecordFailedValidation(ctx, f.ca.ID, c.ID, []string{"failsonly.example.test"}, now0.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	items, err := f.store.RateLedgerReport(ctx, f.org, f.ca.ID, RateLimits{FailedValidationsPerHour: 5}, nil, now0)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, it := range items {
		if it.Limit == LimitFailedValidationsPerHour && it.Scope == "example.test" {
			found = true
			if it.Count != 1 {
				t.Fatalf("count = %d, want 1", it.Count)
			}
		}
	}
	if !found {
		t.Fatalf("failedValidationsPerHour item missing for a certificate that only ever failed validation; items = %+v", items)
	}
}

// TestLedgerStagingRecordsOnly drives a staging-preset issuance whose
// pre-recorded ledger is far over every limit: the rate_ledger step must
// still succeed ("recorded only (staging CA)"), never enforcing.
func TestLedgerStagingRecordsOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	staging, err := f.store.CreateCA(ctx, f.org, CAInput{Name: "LE staging", Preset: "letsencrypt-staging", Resolvers: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	acctID := f.account(t, staging.ID)
	cred := f.credential(t, "cf")
	caID := staging.ID
	c, err := f.store.CreateCertificate(ctx, f.org, CertInput{
		Name: "stg.example.test", CommonName: "stg.example.test",
		Rules:     []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}},
		Overrides: Defaults{CAID: &caID, AccountID: &acctID},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err := f.store.RecordNewOrder(ctx, staging.ID, now0.Add(-time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	fs := &fakeSigner{issued: issuedFor(t, []string{"stg.example.test"}, now0)}
	w := newWorker(f, fs)
	w.Settings = func(context.Context) (IssuanceSettings, error) {
		return IssuanceSettings{CAACheck: false, RateLimits: RateLimits{NewOrdersPer3Hours: 1}}, nil
	}
	if err := w.Issue(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	got, err := f.store.GetCertificate(ctx, f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusActive {
		t.Fatalf("cert = %+v", got)
	}
	a := lastAttempt(t, f, c.ID)
	if stepStatus(a)["rate_ledger"] != challenge.StepSuccess {
		t.Fatalf("rate_ledger step = %q", stepStatus(a)["rate_ledger"])
	}
	var msg string
	for _, s := range a.Steps {
		if s.Name == "rate_ledger" {
			msg = s.Message
		}
	}
	if msg != "recorded only (staging CA)" {
		t.Fatalf("rate_ledger detail = %q", msg)
	}
}

// TestLedgerWrites: a success writes new_order and cert_issued; an
// unauthorized failure writes failed_validation.
func TestLedgerWrites(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred := f.credential(t, "cf")
	c := f.cert(t, []string{"write.example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	fs := &fakeSigner{issued: issuedFor(t, []string{"write.example.test"}, now0)}
	if err := newWorker(f, fs).Issue(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.ledgerCount(t, kindNewOrder); n != 1 {
		t.Fatalf("new_order rows = %d, want 1", n)
	}
	if n := f.ledgerCount(t, kindCertIssued); n != 1 {
		t.Fatalf("cert_issued rows = %d, want 1", n)
	}

	c2 := f.cert(t, []string{"fail.example.test"}, []challenge.RuleSpec{{Match: "*", Method: challenge.MethodDNS01, DNSCredentialID: &cred}})
	fs2 := &fakeSigner{err: &signer.Error{Type: "urn:ietf:params:acme:error:unauthorized", Status: 403, Detail: "nope"}}
	if err := newWorker(f, fs2).Issue(ctx, c2.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.ledgerCount(t, kindFailedValidation); n != 1 {
		t.Fatalf("failed_validation rows = %d, want 1", n)
	}
}

func TestLedgerPrune(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old := now0.Add(-31 * 24 * time.Hour)
	recent := now0.Add(-1 * time.Hour)
	if err := f.store.RecordNewOrder(ctx, f.ca.ID, old); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordNewOrder(ctx, f.ca.ID, recent); err != nil {
		t.Fatal(err)
	}
	n, err := f.store.PruneLedger(ctx, now0.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1", n)
	}
	if got := f.ledgerCount(t, kindNewOrder); got != 1 {
		t.Fatalf("remaining new_order rows = %d, want 1", got)
	}
}

// reserveN runs n concurrent ReserveLedger calls (distinct attempts, one
// shared name set) and returns how many were admitted.
func reserveN(t *testing.T, f *fixture, n int, names []string, limits RateLimits) int {
	t.Helper()
	ctx := context.Background()
	c := f.cert(t, names, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			exceeded, err := f.store.ReserveLedger(ctx, f.ca.ID, c.ID, uuid.New(), names, limits, now0, true)
			if err != nil {
				t.Error(err)
				return
			}
			if exceeded == nil {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return admitted
}

// TestReserveLedgerAtomic: N concurrent attempts against a limit of 3 admit
// exactly 3, whichever limit is the binding one.
func TestReserveLedgerAtomic(t *testing.T) {
	names := []string{"atomic.example.test"}
	for name, limits := range map[string]RateLimits{
		"newOrders":      {NewOrdersPer3Hours: 3},
		"certsPerDomain": {CertsPerRegisteredDomainPerWeek: 3},
		"duplicateCerts": {DuplicateCertsPerWeek: 3},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if got := reserveN(t, f, 8, names, limits); got != 3 {
				t.Fatalf("admitted %d, want 3", got)
			}
		})
	}
}

func TestReserveLedgerIdempotentPerAttempt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	names := []string{"idem.example.test"}
	c := f.cert(t, names, nil)
	attempt := uuid.New()
	for i := 0; i < 2; i++ {
		if exceeded, err := f.store.ReserveLedger(ctx, f.ca.ID, c.ID, attempt, names, RateLimits{NewOrdersPer3Hours: 1}, now0, true); err != nil || exceeded != nil {
			t.Fatalf("call %d: exceeded = %+v, err = %v", i, exceeded, err)
		}
	}
	if f.ledgerCount(t, kindNewOrder) != 1 || f.ledgerCount(t, kindCertIssued) != 1 {
		t.Fatalf("new_order = %d, cert_issued = %d, want 1, 1", f.ledgerCount(t, kindNewOrder), f.ledgerCount(t, kindCertIssued))
	}
}

func TestReserveLedgerExpiredStopsCounting(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	names := []string{"expire.example.test"}
	c := f.cert(t, names, nil)
	limits := RateLimits{CertsPerRegisteredDomainPerWeek: 1}
	if exceeded, err := f.store.ReserveLedger(ctx, f.ca.ID, c.ID, uuid.New(), names, limits, now0, true); err != nil || exceeded != nil {
		t.Fatalf("first: %+v, %v", exceeded, err)
	}
	if exceeded, err := f.store.ReserveLedger(ctx, f.ca.ID, c.ID, uuid.New(), names, limits, now0, true); err != nil || exceeded == nil {
		t.Fatalf("second while reserved: %+v, %v, want exceeded", exceeded, err)
	}
	later := now0.Add(reservationTTL + time.Minute)
	if exceeded, err := f.store.ReserveLedger(ctx, f.ca.ID, c.ID, uuid.New(), names, limits, later, true); err != nil || exceeded != nil {
		t.Fatalf("after expiry: %+v, %v, want admitted", exceeded, err)
	}
}

// TestReserveLedgerConfirmAndRelease: confirm keeps the count (and clears
// the reservation); release drops cert_issued but keeps new_order.
func TestReserveLedgerConfirmAndRelease(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	names := []string{"cr.example.test"}
	c := f.cert(t, names, nil)
	ok, failed := uuid.New(), uuid.New()
	for _, a := range []uuid.UUID{ok, failed} {
		if exceeded, err := f.store.ReserveLedger(ctx, f.ca.ID, c.ID, a, names, RateLimits{}, now0, true); err != nil || exceeded != nil {
			t.Fatalf("reserve: %+v, %v", exceeded, err)
		}
	}
	tx, err := f.store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.ConfirmCertIssued(ctx, tx, f.ca.ID, c.ID, ok, names, now0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ReleaseReservation(ctx, failed); err != nil {
		t.Fatal(err)
	}
	var reserved int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rate_ledger WHERE reserved_until IS NOT NULL`).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if reserved != 0 || f.ledgerCount(t, kindCertIssued) != 1 || f.ledgerCount(t, kindNewOrder) != 2 {
		t.Fatalf("reserved = %d, cert_issued = %d, new_order = %d, want 0, 1, 2", reserved, f.ledgerCount(t, kindCertIssued), f.ledgerCount(t, kindNewOrder))
	}
	// Confirm with nothing reserved (private CA) falls back to an insert.
	tx, err = f.store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.ConfirmCertIssued(ctx, tx, f.ca.ID, c.ID, uuid.New(), names, now0); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if f.ledgerCount(t, kindCertIssued) != 2 {
		t.Fatalf("cert_issued = %d, want 2", f.ledgerCount(t, kindCertIssued))
	}
}

func TestReserveLedgerNotEnforcedRecordsOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	names := []string{"noenf.example.test"}
	c := f.cert(t, names, nil)
	for i := 0; i < 3; i++ {
		if exceeded, err := f.store.ReserveLedger(ctx, f.ca.ID, c.ID, uuid.New(), names, RateLimits{NewOrdersPer3Hours: 1}, now0, false); err != nil || exceeded != nil {
			t.Fatalf("%d: %+v, %v", i, exceeded, err)
		}
	}
	if f.ledgerCount(t, kindNewOrder) != 3 {
		t.Fatalf("new_order = %d, want 3", f.ledgerCount(t, kindNewOrder))
	}
}

func TestPruneLedgerDropsExpiredReservations(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	names := []string{"prune.example.test"}
	c := f.cert(t, names, nil)
	if _, err := f.store.ReserveLedger(ctx, f.ca.ID, c.ID, uuid.New(), names, RateLimits{}, now0, true); err != nil {
		t.Fatal(err)
	}
	// now0 is long past, so the reservation is expired against the DB clock;
	// a cutoff before the row's own timestamp leaves only expiry to prune it.
	if _, err := f.store.PruneLedger(ctx, now0.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if f.ledgerCount(t, kindCertIssued) != 0 || f.ledgerCount(t, kindNewOrder) != 1 {
		t.Fatalf("cert_issued = %d, new_order = %d, want 0, 1", f.ledgerCount(t, kindCertIssued), f.ledgerCount(t, kindNewOrder))
	}
}
