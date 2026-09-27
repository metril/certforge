package challenge

import (
	"context"
	"sync"
	"time"
)

// DefaultHTTPTokenTTL is how long a server http-01 token is servable after
// Present, in case CleanUp is never called (a crashed or superseded
// attempt): long enough for CA validation to reach it, short enough that a
// stale token does not linger.
const DefaultHTTPTokenTTL = 10 * time.Minute

// httpToken is a stored key authorization with its expiry.
type httpToken struct {
	keyAuth string
	expires time.Time
}

// HTTPTokens is the server-side http-01 token store: token -> key
// authorization, backing GET /.well-known/acme-challenge/{token}. Now is
// injected for tests; nil defaults to time.Now.
type HTTPTokens struct {
	ttl time.Duration
	Now func() time.Time

	mu     sync.Mutex
	tokens map[string]httpToken
}

// NewHTTPTokens returns an HTTPTokens store with ttl (<= 0 defaults to
// DefaultHTTPTokenTTL).
func NewHTTPTokens(ttl time.Duration) *HTTPTokens {
	if ttl <= 0 {
		ttl = DefaultHTTPTokenTTL
	}
	return &HTTPTokens{ttl: ttl, Now: time.Now, tokens: map[string]httpToken{}}
}

func (t *HTTPTokens) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Put stores keyAuth for token, servable until the store's TTL elapses.
func (t *HTTPTokens) Put(token, keyAuth string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tokens[token] = httpToken{keyAuth: keyAuth, expires: t.now().Add(t.ttl)}
}

// Get returns the key authorization for token, if present and not expired.
func (t *HTTPTokens) Get(token string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.tokens[token]
	if !ok || !t.now().Before(e.expires) {
		return "", false
	}
	return e.keyAuth, true
}

// Delete removes token outright.
func (t *HTTPTokens) Delete(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.tokens, token)
}

// serverHTTP01 is the server-side http-01 challenge provider: Present
// publishes the key authorization to tokens (served at
// /.well-known/acme-challenge/{token} by the main listener), CleanUp
// retracts it.
type serverHTTP01 struct {
	tokens *HTTPTokens
}

// NewServerHTTP01 returns a ChallengeProvider that serves http-01 challenges
// from this host via tokens.
func NewServerHTTP01(tokens *HTTPTokens) ChallengeProvider {
	return serverHTTP01{tokens: tokens}
}

func (s serverHTTP01) Type() Type { return HTTP01 }

func (s serverHTTP01) Present(_ context.Context, _, token, keyAuth string) error {
	s.tokens.Put(token, keyAuth)
	return nil
}

func (s serverHTTP01) CleanUp(_ context.Context, _, token, _ string) error {
	s.tokens.Delete(token)
	return nil
}

// Timeout is unused by lego for http-01 (no propagation polling: the CA
// fetches the token directly), but ChallengeProvider requires it.
func (s serverHTTP01) Timeout() (time.Duration, time.Duration) {
	return 60 * time.Second, 2 * time.Second
}
