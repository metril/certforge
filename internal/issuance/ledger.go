package issuance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

// rate_ledger.kind values (the table's CHECK constraint).
const (
	kindNewOrder         = "new_order"
	kindCertIssued       = "cert_issued"
	kindFailedValidation = "failed_validation"
)

// Rate limit names: RateLimits' JSON field names, also gen.RateLimitName's
// enum values.
const (
	LimitCertsPerRegisteredDomainPerWeek = "certsPerRegisteredDomainPerWeek"
	LimitDuplicateCertsPerWeek           = "duplicateCertsPerWeek"
	LimitFailedValidationsPerHour        = "failedValidationsPerHour"
	LimitNewOrdersPer3Hours              = "newOrdersPer3Hours"
)

// Ledger windows, one per RateLimits field.
const (
	windowCertsPerDomain    = 7 * 24 * time.Hour
	windowDuplicateCerts    = 7 * 24 * time.Hour
	windowFailedValidations = time.Hour
	windowNewOrders         = 3 * time.Hour
)

// RegisteredDomains returns the sorted, unique registered domains (eTLD+1)
// of names: a leading "*." is stripped before resolving each name, and a
// name publicsuffix cannot resolve (a bare TLD, a single label, or an IP)
// contributes itself. Duplicate-cert scoping (CheckLedger, RateLedgerReport)
// relies on this being deterministic for the same set of names: the first
// (sorted) entry is always the same domain for the same names, staging or
// production, this call or the next.
func RegisteredDomains(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		base := strings.TrimPrefix(strings.ToLower(n), "*.")
		d := registeredDomainOrSelf(base)
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// NamesHash is the hex SHA-256 of names, lower-cased, sorted and joined by
// ",": independent of input order and case, keying the duplicate-certificate
// rate limit to a certificate's exact name set.
func NamesHash(names []string) string {
	lc := make([]string, len(names))
	for i, n := range names {
		lc[i] = strings.ToLower(n)
	}
	sort.Strings(lc)
	sum := sha256.Sum256([]byte(strings.Join(lc, ",")))
	return hex.EncodeToString(sum[:])
}

// LedgerExceeded is CheckLedger's failure: one of limits' trailing-window
// counts already reached its threshold. RetryAt is when the oldest counted
// event leaves the window. IssueWorker.fail unwraps it (it is always
// wrapped in a *signer.Error, urn:ietf:params:acme:error:rateLimited) to
// schedule next_renew_at at RetryAt instead of the usual exponential
// backoff.
type LedgerExceeded struct {
	Limit   string // one of the Limit* constants above
	Count   int
	Max     int
	RetryAt time.Time
}

func (e *LedgerExceeded) Error() string {
	return fmt.Sprintf("rate limit: %s, %d/%d, retry at %s", e.Limit, e.Count, e.Max, e.RetryAt.UTC().Format(time.RFC3339))
}

// RecordNewOrder writes one new_order row for caID (scope: the whole CA).
func (s *Store) RecordNewOrder(ctx context.Context, caID uuid.UUID, at time.Time) error {
	return s.q.InsertLedgerRow(ctx, sqlcgen.InsertLedgerRowParams{CaID: caID, Kind: kindNewOrder, At: at})
}

// RecordCertIssued writes one cert_issued row per registered domain of
// names, all sharing names_hash and certID. tx, when given, is succeed's own
// transaction, so the rows commit or roll back atomically with the stored
// version; tx may be nil (tests, or any caller with no transaction of its
// own) to use the store's own connection pool instead.
func (s *Store) RecordCertIssued(ctx context.Context, tx pgx.Tx, caID, certID uuid.UUID, names []string, at time.Time) error {
	q := s.q
	if tx != nil {
		q = q.WithTx(tx)
	}
	hash := NamesHash(names)
	for _, d := range RegisteredDomains(names) {
		if err := q.InsertLedgerRow(ctx, sqlcgen.InsertLedgerRowParams{CaID: caID, Kind: kindCertIssued,
			RegisteredDomain: d, NamesHash: hash, CertID: &certID, At: at}); err != nil {
			return err
		}
	}
	return nil
}

// RecordFailedValidation writes one failed_validation row per registered
// domain of names.
func (s *Store) RecordFailedValidation(ctx context.Context, caID uuid.UUID, names []string, at time.Time) error {
	for _, d := range RegisteredDomains(names) {
		if err := s.q.InsertLedgerRow(ctx, sqlcgen.InsertLedgerRowParams{CaID: caID, Kind: kindFailedValidation,
			RegisteredDomain: d, At: at}); err != nil {
			return err
		}
	}
	return nil
}

// PruneLedger deletes rows older than before, returning how many were
// removed. Run by the 5-minute certforge_schedule job (ScheduleWorker).
func (s *Store) PruneLedger(ctx context.Context, before time.Time) (int64, error) {
	return s.q.PruneLedger(ctx, before)
}

// CheckLedger compares caID and names' current trailing-window counts
// against limits (each limit checked only while its max is > 0) and returns
// the first one at or over its threshold, nil when none are. Domain-scoped
// limits (certsPerRegisteredDomainPerWeek, failedValidationsPerHour) are
// checked once per registered domain of names; the worst (first found)
// wins. now anchors every window.
func CheckLedger(ctx context.Context, s *Store, caID uuid.UUID, names []string, limits RateLimits, now time.Time) (*LedgerExceeded, error) {
	domains := RegisteredDomains(names)

	if limits.CertsPerRegisteredDomainPerWeek > 0 {
		for _, d := range domains {
			exceeded, err := s.checkDomainLimit(ctx, caID, LimitCertsPerRegisteredDomainPerWeek, kindCertIssued, d,
				limits.CertsPerRegisteredDomainPerWeek, windowCertsPerDomain, now)
			if err != nil || exceeded != nil {
				return exceeded, err
			}
		}
	}
	if limits.DuplicateCertsPerWeek > 0 {
		first := ""
		if len(domains) > 0 {
			first = domains[0]
		}
		exceeded, err := s.checkNamesLimit(ctx, caID, NamesHash(names), first, limits.DuplicateCertsPerWeek, windowDuplicateCerts, now)
		if err != nil || exceeded != nil {
			return exceeded, err
		}
	}
	if limits.FailedValidationsPerHour > 0 {
		for _, d := range domains {
			exceeded, err := s.checkDomainLimit(ctx, caID, LimitFailedValidationsPerHour, kindFailedValidation, d,
				limits.FailedValidationsPerHour, windowFailedValidations, now)
			if err != nil || exceeded != nil {
				return exceeded, err
			}
		}
	}
	if limits.NewOrdersPer3Hours > 0 {
		exceeded, err := s.checkCALimit(ctx, caID, LimitNewOrdersPer3Hours, kindNewOrder, limits.NewOrdersPer3Hours, windowNewOrders, now)
		if err != nil || exceeded != nil {
			return exceeded, err
		}
	}
	return nil, nil
}

// checkDomainLimit is CheckLedger's domain-scoped half (certsPerRegistered
// DomainPerWeek, failedValidationsPerHour): oldest is only queried once max
// is actually reached, so a healthy attempt (the common case, every
// issuance) costs one query per domain per limit, not two.
func (s *Store) checkDomainLimit(ctx context.Context, caID uuid.UUID, limit, kind, domain string, max int, window time.Duration, now time.Time) (*LedgerExceeded, error) {
	since := now.Add(-window)
	n, err := s.q.CountLedgerByDomain(ctx, sqlcgen.CountLedgerByDomainParams{CaID: caID, Kind: kind, RegisteredDomain: domain, At: since})
	if err != nil || n < int64(max) {
		return nil, err
	}
	oldest, err := s.q.OldestLedgerByDomain(ctx, sqlcgen.OldestLedgerByDomainParams{CaID: caID, Kind: kind, RegisteredDomain: domain, At: since})
	if err != nil {
		return nil, err
	}
	return &LedgerExceeded{Limit: limit, Count: int(n), Max: max, RetryAt: oldest.Add(window)}, nil
}

// checkNamesLimit is CheckLedger's duplicateCertsPerWeek half.
func (s *Store) checkNamesLimit(ctx context.Context, caID uuid.UUID, hash, firstDomain string, max int, window time.Duration, now time.Time) (*LedgerExceeded, error) {
	since := now.Add(-window)
	n, err := s.q.CountLedgerByNames(ctx, sqlcgen.CountLedgerByNamesParams{CaID: caID, Kind: kindCertIssued, NamesHash: hash, RegisteredDomain: firstDomain, At: since})
	if err != nil || n < int64(max) {
		return nil, err
	}
	oldest, err := s.q.OldestLedgerByNames(ctx, sqlcgen.OldestLedgerByNamesParams{CaID: caID, Kind: kindCertIssued, NamesHash: hash, RegisteredDomain: firstDomain, At: since})
	if err != nil {
		return nil, err
	}
	return &LedgerExceeded{Limit: LimitDuplicateCertsPerWeek, Count: int(n), Max: max, RetryAt: oldest.Add(window)}, nil
}

// checkCALimit is CheckLedger's newOrdersPer3Hours half (scope: the whole CA).
func (s *Store) checkCALimit(ctx context.Context, caID uuid.UUID, limit, kind string, max int, window time.Duration, now time.Time) (*LedgerExceeded, error) {
	since := now.Add(-window)
	n, err := s.q.CountLedgerByCA(ctx, sqlcgen.CountLedgerByCAParams{CaID: caID, Kind: kind, At: since})
	if err != nil || n < int64(max) {
		return nil, err
	}
	oldest, err := s.q.OldestLedgerByCA(ctx, sqlcgen.OldestLedgerByCAParams{CaID: caID, Kind: kind, At: since})
	if err != nil {
		return nil, err
	}
	return &LedgerExceeded{Limit: limit, Count: int(n), Max: max, RetryAt: oldest.Add(window)}, nil
}

// LedgerItem is one row of GetRateLedger's report.
type LedgerItem struct {
	Limit         string
	Scope         string
	Count         int
	Max           int
	WindowSeconds int
	ResetsAt      *time.Time
}

// RateLedgerReport builds GetRateLedger's items for caID: one
// certsPerRegisteredDomainPerWeek and one failedValidationsPerHour item per
// registered domain orgID has certificates in against caID, one
// newOrdersPer3Hours item (scope "", the whole CA), and — only when cert is
// non-nil — one duplicateCertsPerWeek item for its names. Every count stays
// CA-wide (C5): only which domains appear is scoped to orgID.
func (s *Store) RateLedgerReport(ctx context.Context, orgID, caID uuid.UUID, limits RateLimits, cert *Certificate, now time.Time) ([]LedgerItem, error) {
	var items []LedgerItem

	// The calling org's registered domains against caID. Only cert_issued
	// rows carry a cert_id — a failed_validation row is not tied to any one
	// certificate (RecordFailedValidation runs from fail, which no longer
	// has the succeed transaction to attribute it precisely) — so domain
	// discovery goes through cert_issued history alone and is reused for
	// both domain-scoped items below; each item's count stays CA-wide
	// either way.
	domains, err := s.q.LedgerDomainsInWindow(ctx, sqlcgen.LedgerDomainsInWindowParams{
		CaID: caID, Kind: kindCertIssued, At: now.Add(-windowCertsPerDomain), OrgID: orgID})
	if err != nil {
		return nil, err
	}
	for _, d := range domains {
		it, err := s.reportDomainItem(ctx, caID, LimitCertsPerRegisteredDomainPerWeek, kindCertIssued, d, limits.CertsPerRegisteredDomainPerWeek, windowCertsPerDomain, now)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
		it, err = s.reportDomainItem(ctx, caID, LimitFailedValidationsPerHour, kindFailedValidation, d, limits.FailedValidationsPerHour, windowFailedValidations, now)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
	}

	ordersItem, err := s.reportCAItem(ctx, caID, LimitNewOrdersPer3Hours, kindNewOrder, limits.NewOrdersPer3Hours, windowNewOrders, now)
	if err != nil {
		return nil, err
	}
	items = append(items, ordersItem)

	if cert != nil {
		names := cert.Names()
		domains := RegisteredDomains(names)
		first := ""
		if len(domains) > 0 {
			first = domains[0]
		}
		it, err := s.reportNamesItem(ctx, caID, NamesHash(names), first, strings.Join(names, ", "), limits.DuplicateCertsPerWeek, windowDuplicateCerts, now)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, nil
}

func (s *Store) reportDomainItem(ctx context.Context, caID uuid.UUID, limit, kind, domain string, max int, window time.Duration, now time.Time) (LedgerItem, error) {
	since := now.Add(-window)
	n, err := s.q.CountLedgerByDomain(ctx, sqlcgen.CountLedgerByDomainParams{CaID: caID, Kind: kind, RegisteredDomain: domain, At: since})
	if err != nil {
		return LedgerItem{}, err
	}
	var resets *time.Time
	if n > 0 {
		oldest, err := s.q.OldestLedgerByDomain(ctx, sqlcgen.OldestLedgerByDomainParams{CaID: caID, Kind: kind, RegisteredDomain: domain, At: since})
		if err != nil {
			return LedgerItem{}, err
		}
		t := oldest.Add(window)
		resets = &t
	}
	return LedgerItem{Limit: limit, Scope: domain, Count: int(n), Max: max, WindowSeconds: int(window.Seconds()), ResetsAt: resets}, nil
}

func (s *Store) reportCAItem(ctx context.Context, caID uuid.UUID, limit, kind string, max int, window time.Duration, now time.Time) (LedgerItem, error) {
	since := now.Add(-window)
	n, err := s.q.CountLedgerByCA(ctx, sqlcgen.CountLedgerByCAParams{CaID: caID, Kind: kind, At: since})
	if err != nil {
		return LedgerItem{}, err
	}
	var resets *time.Time
	if n > 0 {
		oldest, err := s.q.OldestLedgerByCA(ctx, sqlcgen.OldestLedgerByCAParams{CaID: caID, Kind: kind, At: since})
		if err != nil {
			return LedgerItem{}, err
		}
		t := oldest.Add(window)
		resets = &t
	}
	return LedgerItem{Limit: limit, Scope: "", Count: int(n), Max: max, WindowSeconds: int(window.Seconds()), ResetsAt: resets}, nil
}

func (s *Store) reportNamesItem(ctx context.Context, caID uuid.UUID, hash, firstDomain, scope string, max int, window time.Duration, now time.Time) (LedgerItem, error) {
	since := now.Add(-window)
	n, err := s.q.CountLedgerByNames(ctx, sqlcgen.CountLedgerByNamesParams{CaID: caID, Kind: kindCertIssued, NamesHash: hash, RegisteredDomain: firstDomain, At: since})
	if err != nil {
		return LedgerItem{}, err
	}
	var resets *time.Time
	if n > 0 {
		oldest, err := s.q.OldestLedgerByNames(ctx, sqlcgen.OldestLedgerByNamesParams{CaID: caID, Kind: kindCertIssued, NamesHash: hash, RegisteredDomain: firstDomain, At: since})
		if err != nil {
			return LedgerItem{}, err
		}
		t := oldest.Add(window)
		resets = &t
	}
	return LedgerItem{Limit: LimitDuplicateCertsPerWeek, Scope: scope, Count: int(n), Max: max, WindowSeconds: int(window.Seconds()), ResetsAt: resets}, nil
}
