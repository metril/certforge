package authn

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Login rate limit defaults: 10 attempts a minute per client, burst 5.
const (
	DefaultLoginPerMinute = 10
	DefaultLoginBurst     = 5
)

// Limiter is an in-memory per-key token bucket. It assumes a single server
// replica (ADR 0006).
type Limiter struct {
	mu        sync.Mutex
	perMinute int
	burst     int
	buckets   map[string]*bucket
	lastSweep time.Time
	now       func() time.Time
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
	// auditedAt is when a rejection last reported first=true; suppressed
	// counts rejections since then (see Rejected).
	auditedAt  time.Time
	suppressed int
}

// RejectWindow is how long Rejected stays quiet after reporting a key.
const RejectWindow = time.Minute

// NewLimiter allows perMinute events per key with the given burst;
// perMinute <= 0 disables limiting.
func NewLimiter(perMinute, burst int) *Limiter {
	return &Limiter{perMinute: perMinute, burst: burst, buckets: map[string]*bucket{}, now: time.Now}
}

// maxBuckets caps the limiter's per-key map so an attacker spraying distinct
// source addresses cannot grow it without bound; once full, Allow evicts the
// single oldest (least recently seen) entry to make room. A var, not a
// const, so tests can shrink it to exercise eviction without 100k keys.
var maxBuckets = 100_000

// Allow takes one token for key, or reports how long until one is free.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perMinute <= 0 {
		return true, 0
	}
	now := l.now()
	l.sweep(now)
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			l.evictOldestLocked()
		}
		b = &bucket{lim: rate.NewLimiter(rate.Every(time.Minute/time.Duration(l.perMinute)), l.burst)}
		l.buckets[key] = b
	}
	b.seen = now
	r := b.lim.ReserveN(now, 1)
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}

// Rejected is called after Allow denies key. It reports first=true for the
// first rejection per key per RejectWindow, together with the number of
// rejections suppressed since the previous report, so callers can audit one
// event per window instead of one per request. It never affects Allow.
func (l *Limiter) Rejected(key string) (first bool, suppressed int) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		return true, 0
	}
	now := l.now()
	if b.auditedAt.IsZero() || now.Sub(b.auditedAt) >= RejectWindow {
		suppressed = b.suppressed
		b.auditedAt, b.suppressed = now, 0
		return true, suppressed
	}
	b.suppressed++
	return false, 0
}

// evictOldestLocked removes the single least-recently-seen bucket. Callers
// must hold l.mu.
func (l *Limiter) evictOldestLocked() {
	var oldestKey string
	var oldestSeen time.Time
	first := true
	for k, b := range l.buckets {
		if first || b.seen.Before(oldestSeen) {
			oldestKey, oldestSeen, first = k, b.seen, false
		}
	}
	if !first {
		delete(l.buckets, oldestKey)
	}
}

// Reconfigure changes the rate and burst applied to new and existing
// per-key buckets; perMinute <= 0 disables limiting. Used to follow the
// authentication section's loginRatePerMinute/loginBurst settings live.
func (l *Limiter) Reconfigure(perMinute, burst int) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perMinute == perMinute && l.burst == burst {
		return
	}
	l.perMinute, l.burst = perMinute, burst
	if perMinute <= 0 {
		return
	}
	now := l.now()
	lim := rate.Every(time.Minute / time.Duration(perMinute))
	for _, b := range l.buckets {
		b.lim.SetLimitAt(now, lim)
		b.lim.SetBurstAt(now, burst)
	}
}

func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		if now.Sub(b.seen) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
}

// LimitKey groups IPv6 clients by /64 so one host cannot rotate addresses
// to dodge the limit.
func LimitKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}
