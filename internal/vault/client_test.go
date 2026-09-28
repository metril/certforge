package vault

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestClient(t *testing.T, addr string, auth Auth) *Client {
	t.Helper()
	c, err := New(Config{Addr: addr, Auth: auth, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestAppRoleLogin covers Login for AppRoleAuth: it POSTs role_id/secret_id
// to the mount's login path and adopts the returned client_token for
// subsequent requests.
func TestAppRoleLogin(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodPost, "/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"auth": map[string]any{
			"client_token": "s.approletoken", "lease_duration": 3600, "renewable": true,
		}})
	})
	fv.handle(http.MethodGet, "/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"ttl": 3600, "policies": []string{"default"}, "renewable": true}})
	})

	c := newTestClient(t, fv.URL(), AppRoleAuth{RoleID: "role-1", SecretID: "secret-1"})
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	var loginBody struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}
	if err := fv.LastBody(http.MethodPost, "/v1/auth/approle/login", &loginBody); err != nil {
		t.Fatalf("LastBody: %v", err)
	}
	if loginBody.RoleID != "role-1" || loginBody.SecretID != "secret-1" {
		t.Fatalf("login body = %+v", loginBody)
	}

	if _, err := c.LookupSelf(context.Background()); err != nil {
		t.Fatalf("LookupSelf: %v", err)
	}
	if got := fv.LastHeader(http.MethodGet, "/v1/auth/token/lookup-self", "X-Vault-Token"); got != "s.approletoken" {
		t.Fatalf("X-Vault-Token = %q, want the logged-in token", got)
	}
}

// TestReloginOn403Once: a request under AppRoleAuth that gets 403 triggers
// exactly one login and one retry, not an unbounded loop.
func TestReloginOn403Once(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodPost, "/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": "fresh-token", "lease_duration": 60, "renewable": true}})
	})
	fv.handleSeq(http.MethodGet, "/v1/transit/keys/kek",
		fakeResponse{status: 403, body: map[string]any{"errors": []string{"permission denied"}}},
		fakeResponse{status: 200, body: map[string]any{"data": map[string]any{"latest_version": 2, "min_decryption_version": 1}}},
	)

	c := newTestClient(t, fv.URL(), AppRoleAuth{RoleID: "r", SecretID: "s"})
	info, err := c.TransitKeyInfo(context.Background(), "transit", "kek")
	if err != nil {
		t.Fatalf("TransitKeyInfo: %v", err)
	}
	if info.LatestVersion != 2 {
		t.Fatalf("LatestVersion = %d, want 2", info.LatestVersion)
	}
	if got := fv.CallCount(http.MethodPost, "/v1/auth/approle/login"); got != 1 {
		t.Fatalf("login calls = %d, want 1", got)
	}
	if got := fv.CallCount(http.MethodGet, "/v1/transit/keys/kek"); got != 2 {
		t.Fatalf("key-info calls = %d, want 2 (403 then retry)", got)
	}
}

// TestTokenRenewalAtHalfTTL: Start's renewal loop waits half the reported
// TTL, driven by an injected clock so the test does not sleep in real time.
func TestTokenRenewalAtHalfTTL(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodGet, "/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"ttl": 100, "policies": []string{}, "renewable": true}})
	})
	fv.handle(http.MethodPost, "/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": "t0", "lease_duration": 100, "renewable": true}})
	})

	c := newTestClient(t, fv.URL(), TokenAuth{Token: "t0"})
	fc := &fakeClock{ch: make(chan time.Time)}
	c.clock = fc

	c.Start(context.Background())
	defer c.Close()

	waitFor(t, func() bool { return len(fc.recorded()) >= 1 })
	got := fc.recorded()[0]
	if got != 50*time.Second {
		t.Fatalf("renewal wait = %v, want 50s (half of 100s ttl)", got)
	}

	fc.fire()
	waitFor(t, func() bool { return fv.CallCount(http.MethodPost, "/v1/auth/token/renew-self") == 1 })
}

// TestRenewLoopSurvivesSeedFailureThenRenews: a Vault blip on Start's first
// call must not kill the renewal loop for good — it should keep trying at
// defaultRenewInterval and actually renew once Vault recovers.
func TestRenewLoopSurvivesSeedFailureThenRenews(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handleSeq(http.MethodPost, "/v1/auth/approle/login",
		fakeResponse{status: 500, body: map[string]any{"errors": []string{"boom"}}},
		fakeResponse{status: 500, body: map[string]any{"errors": []string{"boom"}}},
		fakeResponse{status: 500, body: map[string]any{"errors": []string{"boom"}}},
		fakeResponse{status: 200, body: map[string]any{"auth": map[string]any{
			"client_token": "recovered-token", "lease_duration": 100, "renewable": true,
		}}},
	)

	c := newTestClient(t, fv.URL(), AppRoleAuth{RoleID: "r", SecretID: "s"})
	fc := &fakeClock{ch: make(chan time.Time)}
	c.clock = fc

	c.Start(context.Background())
	defer c.Close()

	// The seed Login exhausts doWithRetry's 3 attempts and fails, but the
	// loop must not exit: it falls into the wait/retry cycle instead.
	waitFor(t, func() bool { return fv.CallCount(http.MethodPost, "/v1/auth/approle/login") == 3 })
	waitFor(t, func() bool { return len(fc.recorded()) >= 1 })
	if got := fc.recorded()[0]; got != defaultRenewInterval {
		t.Fatalf("wait after seed failure = %v, want defaultRenewInterval (%v)", got, defaultRenewInterval)
	}

	fc.fire() // the loop's next attempt: this one succeeds
	waitFor(t, func() bool { return fv.CallCount(http.MethodPost, "/v1/auth/approle/login") == 4 })
	waitFor(t, func() bool { return c.getToken() == "recovered-token" })
}

// TestRetryOn5xxNotOn4xx: connection-level failures and 5xx are retried up
// to 3 attempts with backoff; 4xx is returned immediately.
func TestRetryOn5xxNotOn4xx(t *testing.T) {
	t.Run("5xx then success", func(t *testing.T) {
		fv := newFakeVault()
		defer fv.Close()
		fv.handleSeq(http.MethodGet, "/v1/transit/keys/kek",
			fakeResponse{status: 500, body: map[string]any{"errors": []string{"boom"}}},
			fakeResponse{status: 500, body: map[string]any{"errors": []string{"boom"}}},
			fakeResponse{status: 200, body: map[string]any{"data": map[string]any{"latest_version": 1, "min_decryption_version": 1}}},
		)
		c := newTestClient(t, fv.URL(), TokenAuth{Token: "t"})
		if _, err := c.TransitKeyInfo(context.Background(), "transit", "kek"); err != nil {
			t.Fatalf("TransitKeyInfo: %v", err)
		}
		if got := fv.CallCount(http.MethodGet, "/v1/transit/keys/kek"); got != 3 {
			t.Fatalf("calls = %d, want 3", got)
		}
	})

	t.Run("5xx exhausts retries", func(t *testing.T) {
		fv := newFakeVault()
		defer fv.Close()
		fv.handle(http.MethodGet, "/v1/transit/keys/kek", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 500, map[string]any{"errors": []string{"boom"}})
		})
		c := newTestClient(t, fv.URL(), TokenAuth{Token: "t"})
		if _, err := c.TransitKeyInfo(context.Background(), "transit", "kek"); err == nil {
			t.Fatal("want error after exhausting retries")
		}
		if got := fv.CallCount(http.MethodGet, "/v1/transit/keys/kek"); got != 3 {
			t.Fatalf("calls = %d, want 3 (no more, no less)", got)
		}
	})

	t.Run("4xx not retried", func(t *testing.T) {
		fv := newFakeVault()
		defer fv.Close()
		fv.handle(http.MethodGet, "/v1/transit/keys/kek", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 400, map[string]any{"errors": []string{"bad request"}})
		})
		c := newTestClient(t, fv.URL(), TokenAuth{Token: "t"})
		if _, err := c.TransitKeyInfo(context.Background(), "transit", "kek"); err == nil {
			t.Fatal("want error")
		}
		if got := fv.CallCount(http.MethodGet, "/v1/transit/keys/kek"); got != 1 {
			t.Fatalf("calls = %d, want 1 (never retried)", got)
		}
	})
}

// TestOversizedBodyNotRetried: a response over 1 MiB is an error, but
// unlike a connection error or a 5xx it is deterministic for the endpoint,
// so it must not be retried.
func TestOversizedBodyNotRetried(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	huge := strings.Repeat("a", maxBodySize+1)
	fv.handle(http.MethodGet, "/v1/transit/keys/kek", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"data":{"latest_version":` + huge + `}}`))
	})

	c := newTestClient(t, fv.URL(), TokenAuth{Token: "t"})
	if _, err := c.TransitKeyInfo(context.Background(), "transit", "kek"); err == nil {
		t.Fatal("want error for an oversized body")
	}
	if got := fv.CallCount(http.MethodGet, "/v1/transit/keys/kek"); got != 1 {
		t.Fatalf("calls = %d, want 1 (oversized body is not retried)", got)
	}
}

// TestCloseCancelsInFlightRenewal: Close must not wait out a slow Login the
// renewal loop is in the middle of — it cancels the loop's own context so
// the in-flight HTTP call aborts immediately.
func TestCloseCancelsInFlightRenewal(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodPost, "/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // hang until the request's own context is canceled
	})

	// A long per-request Timeout: without the fix, Close would have to wait
	// out this whole timeout instead of canceling the call outright, making
	// the difference between the two behaviors obvious.
	c, err := New(Config{Addr: fv.URL(), Auth: AppRoleAuth{RoleID: "r", SecretID: "s"}, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.Start(context.Background())

	waitFor(t, func() bool { return fv.CallCount(http.MethodPost, "/v1/auth/approle/login") >= 1 })

	done := make(chan struct{})
	start := time.Now()
	go func() { c.Close(); close(done) }()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("Close took %v, want it to cancel the in-flight login promptly", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return; it is waiting out the in-flight login instead of canceling it")
	}
}

// TestClientRedactsToken: the token and secretId never appear in an error
// string returned by an exported method, even when Vault's own error body
// echoes them back.
func TestClientRedactsToken(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodPost, "/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 400, map[string]any{"errors": []string{
			"invalid credentials for secret_id s3cr3t-id-value and client_token tok-abc123",
		}})
	})

	c := newTestClient(t, fv.URL(), AppRoleAuth{RoleID: "role-1", SecretID: "s3cr3t-id-value"})
	c.token = "tok-abc123" // simulate a previously-known token also present in the error text

	err := c.Login(context.Background())
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	if strings.Contains(msg, "s3cr3t-id-value") {
		t.Fatalf("error leaks secretId: %q", msg)
	}
	if strings.Contains(msg, "tok-abc123") {
		t.Fatalf("error leaks token: %q", msg)
	}
	if !strings.Contains(msg, "[redacted]") {
		t.Fatalf("error not redacted: %q", msg)
	}
}

// TestRedactPreservesAPIErrorStatus: redacting an *APIError must return a
// new *APIError with the same Status, not a bare string — callers (T8/T10/
// T13) use errors.As to branch on Status, and that must keep working even
// when a secret was found and scrubbed.
func TestRedactPreservesAPIErrorStatus(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodPost, "/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 400, map[string]any{"errors": []string{
			"invalid credentials for secret_id s3cr3t-id-value",
		}})
	})

	c := newTestClient(t, fv.URL(), AppRoleAuth{RoleID: "role-1", SecretID: "s3cr3t-id-value"})
	err := c.Login(context.Background())
	if err == nil {
		t.Fatal("want error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As(err, &APIError{}) = false; err = %v (%T)", err, err)
	}
	if apiErr.Status != 400 {
		t.Fatalf("Status = %d, want 400", apiErr.Status)
	}
	if strings.Contains(apiErr.Error(), "s3cr3t-id-value") {
		t.Fatalf("redacted APIError still leaks the secretId: %q", apiErr.Error())
	}
}

// TestHealthStatuses: 200/429/472/473 are reachable (no error, no retry);
// 501/503 are failed (error, no retry either — those codes are meaningful
// states, not transient failures).
func TestHealthStatuses(t *testing.T) {
	cases := []struct {
		status  int
		wantErr bool
	}{
		{200, false},
		{429, false},
		{472, false},
		{473, false},
		{501, true},
		{503, true},
	}
	for _, tc := range cases {
		fv := newFakeVault()
		fv.handle(http.MethodGet, "/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, tc.status, map[string]any{"initialized": true, "sealed": false, "standby": false, "version": "1.18.0"})
		})
		c := newTestClient(t, fv.URL(), TokenAuth{Token: "t"})
		_, err := c.Health(context.Background())
		if (err != nil) != tc.wantErr {
			t.Errorf("status %d: err = %v, wantErr %v", tc.status, err, tc.wantErr)
		}
		if got := fv.CallCount(http.MethodGet, "/v1/sys/health"); got != 1 {
			t.Errorf("status %d: calls = %d, want 1 (never retried)", tc.status, got)
		}
		fv.Close()
	}
}

// TestNamespaceHeader: X-Vault-Namespace is sent only when Namespace is set.
func TestNamespaceHeader(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodGet, "/v1/transit/keys/kek", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"latest_version": 1, "min_decryption_version": 1}})
	})

	c, err := New(Config{Addr: fv.URL(), Namespace: "team-a", Auth: TokenAuth{Token: "t"}, Timeout: time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.TransitKeyInfo(context.Background(), "transit", "kek"); err != nil {
		t.Fatalf("TransitKeyInfo: %v", err)
	}
	if got := fv.LastHeader(http.MethodGet, "/v1/transit/keys/kek", "X-Vault-Namespace"); got != "team-a" {
		t.Fatalf("X-Vault-Namespace = %q, want team-a", got)
	}

	c2, err := New(Config{Addr: fv.URL(), Auth: TokenAuth{Token: "t"}, Timeout: time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c2.TransitKeyInfo(context.Background(), "transit", "kek"); err != nil {
		t.Fatalf("TransitKeyInfo: %v", err)
	}
	if got := fv.LastHeader(http.MethodGet, "/v1/transit/keys/kek", "X-Vault-Namespace"); got != "" {
		t.Fatalf("X-Vault-Namespace = %q, want empty when unset", got)
	}
}

// fakeClock lets TestTokenRenewalAtHalfTTL control Start's renewal loop
// without waiting in real time: After records the requested duration and
// returns a channel the test fires manually via fire().
type fakeClock struct {
	ch   chan time.Time
	durs []time.Duration
	lock sync.Mutex
}

func (f *fakeClock) After(d time.Duration) <-chan time.Time {
	f.lock.Lock()
	f.durs = append(f.durs, d)
	f.lock.Unlock()
	return f.ch
}

func (f *fakeClock) recorded() []time.Duration {
	f.lock.Lock()
	defer f.lock.Unlock()
	out := make([]time.Duration, len(f.durs))
	copy(out, f.durs)
	return out
}

func (f *fakeClock) fire() { f.ch <- time.Now() }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
