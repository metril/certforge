// Package httpx is the outbound HTTP client shared by every notification
// notifier (webhook, Discord, ntfy, Home Assistant) and by external
// monitors' dial policy: SSRF-safe dialing (CheckURL/CheckHost/DialControl),
// no redirect following, bounded retries on connection errors and 5xx/429,
// a capped response body, and secret redaction of any error string before
// it is stored or logged (global constraints, Secrets row).
package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
	"unicode/utf8"
)

// MaxBody bounds how much of a response body Do reads (contract).
const MaxBody = 64 << 10

// Attempts is the retry budget for a connection error, a 5xx or a 429
// response (contract).
const Attempts = 3

// Timeout is the default per-attempt timeout when Options.Timeout is zero.
const Timeout = 10 * time.Second

// scrubBodyLimit is how much of a failed response's body is kept in the
// resulting error (contract: "status <n>: <first 200 bytes, scrubbed>").
const scrubBodyLimit = 200

// Options configures a new Client.
type Options struct {
	// CAPEM is additional PEM-encoded certificates appended to the system
	// root pool (a channel or monitor's own caPem field). It only adds
	// trust: TLS verification is never disabled.
	CAPEM string
	// AllowLoopback re-admits loopback and link-local hosts (the
	// "notifications" settings section's allowLoopbackUrls), except the
	// cloud-metadata addresses, which DialControl always blocks.
	AllowLoopback bool
	// Timeout bounds each individual attempt. Zero uses Timeout.
	Timeout time.Duration
}

// Client is a *http.Client wired for outbound notifier and monitor
// requests: no redirects, no proxy, an SSRF-checked dialer, and bounded
// retries (Do).
type Client struct {
	http          *http.Client
	allowLoopback bool
	// dialer is kept (not just handed to http.Transport and dropped) so a
	// same-package test can redirect DNS resolution through a stub server
	// via dialer.Resolver — batch-1 review finding 6:
	// TestDialRejectsLoopbackAfterResolve needs a hostname that actually
	// resolves to a blocked address, not a literal IP passed straight to
	// DialControl, to prove the dial-time recheck (not just CheckURL)
	// catches DNS rebinding.
	dialer *net.Dialer
}

// New builds a Client from opts. It never contacts the network.
func New(opts Options) (*Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if opts.CAPEM != "" && !pool.AppendCertsFromPEM([]byte(opts.CAPEM)) {
		return nil, errors.New("httpx: ca bundle contains no PEM certificates")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = Timeout
	}
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: DialControl(opts.AllowLoopback),
	}
	transport := &http.Transport{
		Proxy:           nil, // contract: ignores proxy env vars
		DialContext:     dialer.DialContext,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	return &Client{
		allowLoopback: opts.AllowLoopback,
		dialer:        dialer,
		http: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// contract: httpx never follows redirects; a 3xx is a
				// failure, handled by Do reading the (unfollowed)
				// redirect response's own status.
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Do sends one logical request, retrying a connection error, a 5xx or a
// 429 response up to Attempts times with 200ms*2^n backoff capped by ctx.
// A 3xx (redirects are never followed) or a non-retryable 4xx returns
// immediately. The returned error, when non-nil, is
// "status <n>: <first 200 bytes of the body, scrubbed>" for an HTTP
// response, or the underlying transport error otherwise.
func (c *Client) Do(ctx context.Context, method, rawURL string, h http.Header, body []byte) (int, error) {
	if err := CheckURL(rawURL, c.allowLoopback); err != nil {
		return 0, err
	}
	// host-only, never the full rawURL: a webhook/ntfy/Home Assistant URL
	// or its query string can itself carry a secret (a token, a signed
	// path), so every error this method returns names only the host, not
	// the path or query (batch-1 review finding 1).
	host := ""
	if u, err := url.Parse(rawURL); err == nil {
		host = u.Host
	}
	var lastStatus int
	var lastErr error
	for attempt := 1; attempt <= Attempts; attempt++ {
		if attempt > 1 {
			if err := sleepCtx(ctx, backoff(attempt-1)); err != nil {
				return lastStatus, err
			}
		}
		status, respBody, err := c.attempt(ctx, method, rawURL, host, h, body)
		if err != nil {
			lastStatus, lastErr = 0, err
			continue
		}
		if status >= 200 && status < 300 {
			return status, nil
		}
		lastStatus = status
		lastErr = fmt.Errorf("httpx: status %d: %s", status, scrub(respBody))
		if status == http.StatusTooManyRequests || status >= 500 {
			continue
		}
		return lastStatus, lastErr
	}
	return lastStatus, lastErr
}

func (c *Client) attempt(ctx context.Context, method, rawURL, host string, h http.Header, body []byte) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return 0, nil, fmt.Errorf("httpx: build request for %s: %w", host, err)
	}
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// c.http.Do wraps a transport failure in *url.Error, whose own
		// Error() embeds the full request URL verbatim (path, query
		// string and all) — unwrap to the underlying cause and rebuild
		// the message from host alone, so a webhook/ntfy/Home Assistant
		// URL's secret query or path parameter never reaches a stored or
		// logged error (batch-1 review finding 1).
		cause := error(err)
		var uerr *url.Error
		if errors.As(err, &uerr) {
			cause = uerr.Err
		}
		return 0, nil, fmt.Errorf("httpx: %s %s: %w", method, host, cause)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return 0, nil, fmt.Errorf("httpx: read response: %w", err)
	}
	return resp.StatusCode, data, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func backoff(attempt int) time.Duration {
	return 200 * time.Millisecond * time.Duration(uint(1)<<uint(attempt-1)) //nolint:gosec // attempt is 1..Attempts-1, no overflow risk
}

// scrub bounds a response body to scrubBodyLimit bytes (trimming back
// further if the cut landed inside a multi-byte rune) and replaces control
// characters (including CR/LF, which could otherwise forge extra lines
// into a stored last_error or a log line) with a space.
func scrub(body []byte) string {
	if len(body) > scrubBodyLimit {
		body = body[:scrubBodyLimit]
	}
	s := string(body)
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size != 1 {
			break
		}
		s = s[:len(s)-1]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		out = append(out, r)
	}
	return string(out)
}
