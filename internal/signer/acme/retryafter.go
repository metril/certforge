package acme

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// retryAfterTransport remembers the largest Retry-After seen on a 429 or 503
// response. lego's ProblemDetails drops response headers, so this is how a
// rateLimited error keeps the CA's requested delay.
type retryAfterTransport struct {
	base http.RoundTripper
	now  func() time.Time
	mu   sync.Mutex
	max  time.Duration
}

func (t *retryAfterTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil || (resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable) {
		return resp, err
	}
	if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), t.now()); ok {
		t.mu.Lock()
		if d > t.max {
			t.max = d
		}
		t.mu.Unlock()
	}
	return resp, nil
}

// RetryAfter returns the largest delay requested so far (0 if none).
func (t *retryAfterTransport) RetryAfter() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.max
}

// maxRetryAfter caps a CA's requested delay. It mirrors issuance's
// backoffCap, which acme cannot import (issuance imports this package).
const maxRetryAfter = 24 * time.Hour

// parseRetryAfter accepts delta-seconds or an HTTP-date (RFC 9110 10.2.3).
// The result is clamped to maxRetryAfter.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		if secs > int(maxRetryAfter/time.Second) {
			return maxRetryAfter, true
		}
		return time.Duration(secs) * time.Second, true
	}
	at, err := http.ParseTime(v)
	if err != nil {
		return 0, false
	}
	d := at.Sub(now)
	if d < 0 {
		d = 0
	}
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d, true
}
