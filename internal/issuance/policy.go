package issuance

import (
	"time"

	"github.com/metril/certforge/internal/signer"
)

// NextRenewAt applies the renewal policy to a certificate lifetime. The
// result is never earlier than half the lifetime (so a 30-day policy on a
// 6-day certificate does not renew in a loop) and never before now+1h.
func NextRenewAt(p RenewPolicy, notBefore, notAfter, now time.Time) time.Time {
	life := notAfter.Sub(notBefore)
	var at time.Time
	switch p.Mode {
	case RenewDays:
		at = notAfter.Add(-time.Duration(p.Value) * 24 * time.Hour)
	default:
		v := p.Value
		if v <= 0 || v >= 100 {
			v = 33
		}
		// life/100 first: life*time.Duration(v) can overflow int64 nanoseconds
		// for a large lifetime before the /100 brings it back down.
		at = notAfter.Add(-(life / 100 * time.Duration(v)))
	}
	if floor := notBefore.Add(life / 2); at.Before(floor) {
		at = floor
	}
	if floor := now.Add(time.Hour); at.Before(floor) {
		at = floor
	}
	return at
}

// NextRenewAtARI applies an ACME Renewal Information window on top of the
// renewal-policy date policyAt: renewal only ever moves earlier, never
// later. When w is non-nil and its End is before policyAt, the result is a
// uniform random instant in [max(w.Start, now), max(w.End, now)] — a
// window that has already fully passed (both ends before now) collapses to
// now itself; otherwise the result is policyAt, unchanged. rnd returns a
// value in [0,1).
func NextRenewAtARI(policyAt time.Time, w *signer.Window, now time.Time, rnd func() float64) time.Time {
	if w == nil || !w.End.Before(policyAt) {
		return policyAt
	}
	lo, hi := w.Start, w.End
	if lo.Before(now) {
		lo = now
	}
	if hi.Before(now) {
		hi = now
	}
	if !hi.After(lo) {
		return lo
	}
	return lo.Add(time.Duration(rnd() * float64(hi.Sub(lo))))
}

const (
	backoffBase = 5 * time.Minute
	backoffCap  = 24 * time.Hour
)

// Backoff is min(5m·2^(failures-1), 24h) with ±20% jitter; a longer
// Retry-After from the CA wins. rnd returns a value in [0,1).
func Backoff(failures int, retryAfter time.Duration, rnd func() float64) time.Duration {
	if failures < 1 {
		failures = 1
	}
	d := backoffBase
	for i := 1; i < failures && d < backoffCap; i++ {
		d *= 2
	}
	if d > backoffCap {
		d = backoffCap
	}
	j := time.Duration(float64(d) * (0.8 + 0.4*rnd()))
	if retryAfter > j {
		return retryAfter
	}
	return j
}
