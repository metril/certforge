package issuance

import "time"

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
		at = notAfter.Add(-life * time.Duration(v) / 100)
	}
	if floor := notBefore.Add(life / 2); at.Before(floor) {
		at = floor
	}
	if floor := now.Add(time.Hour); at.Before(floor) {
		at = floor
	}
	return at
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
