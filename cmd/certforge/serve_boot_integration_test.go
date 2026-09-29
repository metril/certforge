//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/db/dbtest"
)

// freeAddr returns a "127.0.0.1:port" address whose port was free at the
// moment of the call (closed immediately after), the same short-window-race
// tradeoff every "find a free port for a test server" helper accepts.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// waitFor polls cond every 200ms until it returns true or timeout elapses
// (bounded, global-constraints style), failing the test on timeout.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// bootClient is a tiny JSON/cookie HTTP client against a running serve
// instance, doing just enough of what internal/api's own testEnv does
// (session cookie jar, X-CSRF-Token header) to drive the real HTTP API
// over the network instead of api.NewRouter wired directly to an
// httptest.Server.
type bootClient struct {
	t      *testing.T
	base   string
	client *http.Client
	csrf   string
}

func newBootClient(t *testing.T, base string) *bootClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &bootClient{t: t, base: base, client: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
}

func (c *bootClient) do(method, path string, body any) (*http.Response, []byte) {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, rdr)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		c.t.Fatal(rerr)
	}
	return resp, out
}

// TestServeBootsWithOps boots the real cmd/certforge server (runServe,
// exactly as `certforge serve` runs it — no fixture, no fake wiring) against
// a fresh test database, then proves the Phase 6A wiring task-14-brief.md
// asks for: /readyz reports ready, GET /meta/schemas lists all five
// notifiers (the SettingsFunc seams wired in serve.go), /metrics 404s while
// the "prometheus" section is disabled (its default), and — the strongest
// proof the wiring is real rather than merely present — creating a
// certificate against a freshly created local CA drives an actual
// certforge_issue job through the real river queue, whose success calls
// issueWorker.Listeners' third VersionListener (notify.Sources.OnVersion),
// which emits cert.issued through the shared notify.Emitter, which enqueues
// and runs a real certforge_notify_deliver job that POSTs the event to an
// httptest webhook receiver. Nothing in this chain is mocked below the
// httptest webhook target itself.
func TestServeBootsWithOps(t *testing.T) {
	url := dbtest.URL(t)
	httpAddr := freeAddr(t)
	agentAddr := freeAddr(t)
	t.Setenv("CF_DATABASE_URL", url)
	t.Setenv("CF_KEK", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	t.Setenv("CF_KEK_FILE", "")
	t.Setenv("CF_LISTEN_HTTP", httpAddr)
	t.Setenv("CF_LISTEN_AGENT", agentAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runServe(ctx, nil, io.Discard) }()

	base := "http://" + httpAddr
	waitFor(t, 30*time.Second, "/readyz 200", func() bool {
		resp, err := http.Get(base + "/readyz") //nolint:noctx,bodyclose // short-lived readiness poll
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	// GET /metrics 404s while "prometheus" is disabled (its default): the
	// route and handler are wired (deps.Metrics/metrics.Middleware), but
	// nothing has enabled the section yet.
	if resp, err := http.Get(base + "/metrics"); err != nil { //nolint:noctx,bodyclose // one-shot check
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET /metrics = %d, want 404 (prometheus disabled)", resp.StatusCode)
		}
	}

	c := newBootClient(t, base)
	setupIn := map[string]string{
		"adminPassword": "correct horse battery staple", "orgName": "Boot Org",
		"orgSlug": "boot-org", "baseUrl": "http://example.test",
	}
	resp, body := c.do(http.MethodPost, "/api/v1/setup/complete", setupIn) //nolint:bodyclose // bootClient.do closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup/complete: %d %s", resp.StatusCode, body)
	}
	var me struct {
		Orgs []struct {
			ID string `json:"id"`
		} `json:"orgs"`
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(body, &me); err != nil || len(me.Orgs) != 1 || me.CsrfToken == "" {
		t.Fatalf("setup/complete response: %s (err %v)", body, err)
	}
	c.csrf = me.CsrfToken
	orgID := me.Orgs[0].ID

	// GET /meta/schemas lists all five notifiers: proves notifyReg's
	// SettingsFunc seams (webhook/discord/ntfy/homeassistant/smtp) are
	// wired the same way cmd/certforge/serve.go registers them.
	resp, body = c.do(http.MethodGet, "/api/v1/meta/schemas", nil) //nolint:bodyclose // bootClient.do closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("meta/schemas: %d %s", resp.StatusCode, body)
	}
	var schemas struct {
		Notifiers []struct {
			Code string `json:"code"`
		} `json:"notifiers"`
	}
	if err := json.Unmarshal(body, &schemas); err != nil {
		t.Fatal(err)
	}
	wantNotifiers := map[string]bool{"webhook": false, "discord": false, "ntfy": false, "homeassistant": false, "smtp": false}
	for _, n := range schemas.Notifiers {
		if _, ok := wantNotifiers[n.Code]; ok {
			wantNotifiers[n.Code] = true
		}
	}
	for code, seen := range wantNotifiers {
		if !seen {
			t.Errorf("meta/schemas notifiers missing %s", code)
		}
	}

	// allowLoopbackUrls: the webhook below targets an httptest.Server on
	// 127.0.0.1, which the SSRF policy otherwise rejects at both create and
	// dial time (Deviations R3/R5).
	if resp, body = c.do(http.MethodPut, "/api/v1/settings/notifications", map[string]bool{"allowLoopbackUrls": true}); resp.StatusCode != http.StatusOK { //nolint:bodyclose // bootClient.do closes the body
		t.Fatalf("settings notifications: %d %s", resp.StatusCode, body)
	}

	events := make(chan map[string]any, 4)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev map[string]any
		_ = json.NewDecoder(r.Body).Decode(&ev)
		events <- ev
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	channelIn := map[string]any{"name": "boot-test-webhook", "type": "webhook", "config": map[string]any{"url": webhook.URL}}
	if resp, body = c.do(http.MethodPost, fmt.Sprintf("/api/v1/orgs/%s/channels", orgID), channelIn); resp.StatusCode != http.StatusCreated { //nolint:bodyclose // bootClient.do closes the body
		t.Fatalf("createChannel: %d %s", resp.StatusCode, body)
	}

	// A localca CA signs offline, synchronously, no ACME/network round trip
	// (internal/signer/localca): the fastest real (non-mocked) path from a
	// created certificate to a delivered cert.issued event.
	caIn := map[string]any{"name": "Boot Test Root", "type": "localca",
		"config": map[string]any{"subject": map[string]any{"commonName": "Boot Test Root"}}}
	resp, body = c.do(http.MethodPost, fmt.Sprintf("/api/v1/orgs/%s/cas", orgID), caIn) //nolint:bodyclose // bootClient.do closes the body
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("createCa: %d %s", resp.StatusCode, body)
	}
	var ca struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ca); err != nil {
		t.Fatal(err)
	}

	certIn := map[string]any{
		"name": "boot-test-leaf", "commonName": "boot-test-leaf.example.test",
		"overrides": map[string]any{"caId": ca.ID},
	}
	if resp, body = c.do(http.MethodPost, fmt.Sprintf("/api/v1/orgs/%s/certificates", orgID), certIn); resp.StatusCode != http.StatusCreated { //nolint:bodyclose // bootClient.do closes the body
		t.Fatalf("createCertificate: %d %s", resp.StatusCode, body)
	}

	// The real river queue (riverClient.Start, running since boot) picks up
	// CreateCertificate's own enqueued certforge_issue job, issues against
	// the local CA, and — through issueWorker.Listeners' third
	// VersionListener — emits cert.issued, which a real
	// certforge_notify_deliver job posts to the webhook above.
	var got map[string]any
	select {
	case got = <-events:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the webhook to receive cert.issued")
	}
	if kind, _ := got["kind"].(string); kind != "cert.issued" {
		t.Fatalf("event kind = %v, want cert.issued (event: %v)", got["kind"], got)
	}
	if summary, _ := got["summary"].(string); !strings.Contains(summary, "boot-test-leaf.example.test") {
		t.Fatalf("event summary = %q, want it to name the certificate", summary)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runServe: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for runServe to shut down")
	}
}
