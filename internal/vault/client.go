package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// defaultTimeout matches the "vault" settings section's own default
// (Task 1's vault.schema.json timeoutSeconds), used when Config.Timeout is
// left zero.
const defaultTimeout = 10 * time.Second

// defaultRenewInterval is Start's fallback wait when no lease TTL is known
// yet (should not happen in practice: Start seeds the lease before looping).
const defaultRenewInterval = 30 * time.Second

// maxBodySize bounds how much of a Vault response body the client will
// read; anything larger is an error rather than an unbounded allocation.
const maxBodySize = 1 << 20 // 1 MiB

// errBodyTooLarge is returned by rawDo when a response exceeds maxBodySize.
// It is deterministic for a given endpoint, so doWithRetry never retries it
// (unlike a connection error, retrying would just fail the same way three
// times slower).
var errBodyTooLarge = errors.New("vault: response body too large")

// maxAttempts is the retry budget for connection errors and 5xx responses
// (Contract: "3 attempts with backoff 200 ms·2^n").
const maxAttempts = 3

// Config configures a new Client.
type Config struct {
	// Addr is Vault's base URL, e.g. "https://vault.example.com:8200".
	Addr string
	// Namespace is a Vault Enterprise namespace, sent as X-Vault-Namespace
	// when set.
	Namespace string
	// CAPEM is additional PEM-encoded certificates appended to the system
	// root pool for verifying Vault's TLS. It only adds trust: TLS
	// verification is never disabled.
	CAPEM string
	// Timeout bounds each individual HTTP attempt. Zero uses defaultTimeout.
	Timeout time.Duration
	// Auth selects how the client logs in to Vault.
	Auth Auth
	// Log receives renewal-loop warnings (never a token or secret). Nil
	// discards them.
	Log *slog.Logger
}

// Client talks to Vault's (or OpenBao's) HTTP API for Transit, KV v2, PKI
// and token/AppRole auth. Every exported method redacts secrets from any
// error it returns (see Redact).
type Client struct {
	Addr      string
	Namespace string
	CA        *x509.CertPool
	Timeout   time.Duration
	auth      Auth

	httpClient *http.Client
	clock      clock
	log        *slog.Logger

	mu           sync.Mutex
	token        string
	leaseSeconds int
	renewable    bool
	cancelLoop   context.CancelFunc
	wg           sync.WaitGroup
}

// New builds a Client from cfg. It does not contact Vault: call Login (or
// Start, which logs in as needed) before making requests under AppRoleAuth.
func New(cfg Config) (*Client, error) {
	if cfg.Addr == "" {
		return nil, errors.New("vault: address is required")
	}
	switch a := cfg.Auth.(type) {
	case TokenAuth:
		if a.Token == "" {
			return nil, errors.New("vault: token auth requires a token")
		}
	case AppRoleAuth:
		if a.RoleID == "" || a.SecretID == "" {
			return nil, errors.New("vault: approle auth requires a role id and secret id")
		}
	default:
		return nil, fmt.Errorf("vault: unsupported auth type %T", cfg.Auth)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if cfg.CAPEM != "" && !pool.AppendCertsFromPEM([]byte(cfg.CAPEM)) {
		return nil, errors.New("vault: ca bundle contains no PEM certificates")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	c := &Client{
		Addr:       strings.TrimRight(cfg.Addr, "/"),
		Namespace:  cfg.Namespace,
		CA:         pool,
		Timeout:    timeout,
		auth:       cfg.Auth,
		httpClient: &http.Client{Transport: base},
		clock:      realClock{},
		log:        cfg.Log,
	}
	if t, ok := cfg.Auth.(TokenAuth); ok {
		c.token = t.Token
	}
	return c, nil
}

// Start begins a background renewal loop: renewable tokens are renewed at
// half their TTL, AppRole logins are refreshed the same way by logging in
// again. Close stops it. Calling Start twice is a no-op.
//
// The loop runs on its own context, derived from ctx but canceled by Close
// independently of it: without that, Close would have to wait out whatever
// Login/RenewSelf call the loop happened to be in the middle of (up to
// maxAttempts retries plus backoff on ctx), since those calls run on the
// loop's context, not a per-call one Close could cancel separately.
func (c *Client) Start(ctx context.Context) {
	c.mu.Lock()
	if c.cancelLoop != nil {
		c.mu.Unlock()
		return
	}
	loopCtx, cancel := context.WithCancel(ctx)
	c.cancelLoop = cancel
	c.mu.Unlock()

	c.wg.Add(1)
	go c.renewLoop(loopCtx)
}

// Close stops the renewal loop started by Start and waits for it to exit.
// Calling Close without a prior Start, or twice, is a no-op.
func (c *Client) Close() {
	c.mu.Lock()
	cancel := c.cancelLoop
	c.cancelLoop = nil
	c.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	c.wg.Wait()
}

func (c *Client) renewLoop(ctx context.Context) {
	defer c.wg.Done()

	// A seed failure (a Vault blip right at Start) is not fatal: fall
	// through into the loop below, which waits defaultRenewInterval (no
	// lease is known yet) and tries again, rather than exiting the renewal
	// loop for good and leaving a renewable token to expire unrenewed.
	if c.getToken() == "" {
		c.warn("vault login failed", c.Login(ctx))
	} else {
		c.warn("vault token lookup failed", c.refreshLease(ctx))
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.clock.After(c.renewInterval()):
		}

		c.mu.Lock()
		renewable := c.renewable
		c.mu.Unlock()

		switch {
		case renewable:
			if err := c.RenewSelf(ctx); err != nil {
				c.warn("vault token renewal failed", err)
			} else {
				c.warn("vault token lookup failed", c.refreshLease(ctx))
			}
		default:
			if _, ok := c.auth.(AppRoleAuth); ok {
				c.warn("vault login failed", c.Login(ctx))
			} else {
				c.warn("vault token lookup failed", c.refreshLease(ctx))
			}
		}
	}
}

// warn logs a renewal-loop failure (err is already redacted by the client's
// exported methods); a nil err, a nil logger, or a cancelled loop is silent.
func (c *Client) warn(msg string, err error) {
	if err == nil || c.log == nil || errors.Is(err, context.Canceled) {
		return
	}
	c.log.Warn(msg, "addr", c.Addr, "err", err)
}

func (c *Client) refreshLease(ctx context.Context) error {
	info, err := c.LookupSelf(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.leaseSeconds = int(info.TTL / time.Second)
	c.renewable = info.Renewable
	c.mu.Unlock()
	return nil
}

func (c *Client) renewInterval() time.Duration {
	c.mu.Lock()
	lease := c.leaseSeconds
	c.mu.Unlock()
	if lease <= 0 {
		return defaultRenewInterval
	}
	return time.Duration(lease) * time.Second / 2
}

func (c *Client) getToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

func (c *Client) setToken(tok string) {
	c.mu.Lock()
	c.token = tok
	c.mu.Unlock()
}

// clock abstracts time.After so Start's renewal loop can be driven
// deterministically in tests (TestTokenRenewalAtHalfTTL injects a fake).
type clock interface {
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// APIError is a non-2xx answer from Vault.
type APIError struct {
	Status int
	Errors []string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("vault: status %d: %s", e.Status, strings.Join(e.Errors, "; "))
}

func parseAPIError(status int, body []byte) *APIError {
	var payload struct {
		Errors []string `json:"errors"`
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &payload)
	}
	if len(payload.Errors) == 0 {
		if trimmed := strings.TrimSpace(string(body)); trimmed != "" {
			payload.Errors = []string{trimmed}
		} else {
			payload.Errors = []string{http.StatusText(status)}
		}
	}
	return &APIError{Status: status, Errors: payload.Errors}
}

// requestOpts tunes doJSON/doWithRetry beyond the default "2xx succeeds,
// 4xx fails immediately, 5xx/connection errors retry 3 times" behavior.
type requestOpts struct {
	// accept lists extra statuses (besides 2xx) that count as success.
	accept []int
	// noRetry lists >=500 statuses that must not be retried even though
	// they are >=500 (Health's 501/503: meaningful states, not failures).
	noRetry []int
	// noRelogin suppresses the one-shot 403-under-AppRole relogin+retry;
	// set by Login itself to avoid recursing into its own retry path.
	noRelogin bool
}

func isAccepted(status int, accept []int) bool {
	if status >= 200 && status < 300 {
		return true
	}
	return slices.Contains(accept, status)
}

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
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
	return 200 * time.Millisecond * time.Duration(uint(1)<<uint(attempt-1))
}

// doWithRetry sends one logical request, retrying connection errors and
// unaccepted 5xx responses up to maxAttempts times with exponential
// backoff, capped by ctx. 4xx (and any status in opts.noRetry) returns
// immediately without retrying.
func (c *Client) doWithRetry(ctx context.Context, method, path string, body any, opts requestOpts) (int, []byte, error) {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			if err := c.sleep(ctx, backoff(attempt-1)); err != nil {
				return 0, nil, err
			}
		}
		status, respBody, err := c.rawDo(ctx, method, path, body)
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				return 0, nil, err
			}
			lastErr = err
			continue
		}
		if isAccepted(status, opts.accept) {
			return status, respBody, nil
		}
		apiErr := parseAPIError(status, respBody)
		if status >= 500 && !slices.Contains(opts.noRetry, status) {
			lastErr = apiErr
			continue
		}
		return status, respBody, apiErr
	}
	return 0, nil, lastErr
}

// doJSON is doWithRetry plus JSON decoding and the one-shot 403 relogin
// under AppRoleAuth.
func (c *Client) doJSON(ctx context.Context, method, path string, body, out any, opts requestOpts) error {
	_, respBody, err := c.doWithRetry(ctx, method, path, body, opts)
	if err != nil {
		var apiErr *APIError
		if !opts.noRelogin && errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden {
			if _, ok := c.auth.(AppRoleAuth); ok {
				if lerr := c.Login(ctx); lerr == nil {
					_, respBody, err = c.doWithRetry(ctx, method, path, body, opts)
				}
			}
		}
	}
	if err != nil {
		return err
	}
	if out != nil && len(respBody) > 0 {
		if jerr := json.Unmarshal(respBody, out); jerr != nil {
			return fmt.Errorf("vault: decode response: %w", jerr)
		}
	}
	return nil
}

func (c *Client) rawDo(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("vault: encode request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}

	reqCtx := ctx
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(reqCtx, method, c.Addr+path, rdr)
	if err != nil {
		return 0, nil, fmt.Errorf("vault: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok := c.getToken(); tok != "" {
		req.Header.Set("X-Vault-Token", tok)
	}
	if c.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.Namespace)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("vault: request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return 0, nil, fmt.Errorf("vault: read response: %w", err)
	}
	if len(data) > maxBodySize {
		return 0, nil, errBodyTooLarge
	}
	return resp.StatusCode, data, nil
}
