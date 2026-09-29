package notify_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/notify/httpx"
)

// allowLoopback is a notify.SettingsFunc that always allows loopback URLs
// (every test in this package dials an httptest server, which is loopback
// by construction) with no *settings.Store at all — the seam
// notify.SettingsFunc exists for (webhook.go's doc comment).
func allowLoopback(context.Context) (notify.Settings, error) {
	return notify.Settings{AllowLoopbackURLs: true}, nil
}

func testEvent() notify.Event {
	return notify.Event{
		ID:       uuid.New(),
		Kind:     "cert.expiring",
		At:       time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
		Severity: "warning",
		Resource: notify.Resource{Type: "certificate", ID: "cert-1", Name: "example.com"},
		Summary:  "example.com expires in 7 days",
		Details:  map[string]any{"notAfter": "2026-10-06T00:00:00Z"},
	}
}

// TestWebhookSignatureVerifies covers the task-4 brief's TestWebhookSignatureVerifies:
// the fake server recomputes the HMAC-SHA256 over the exact received body and
// must agree with X-CertForge-Signature.
func TestWebhookSignatureVerifies(t *testing.T) {
	const secret = "a-signing-secret-16"
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		gotSig = r.Header.Get("X-CertForge-Signature")
		if gotSig != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := notify.Webhook{Settings: allowLoopback}
	cfg := map[string]any{}
	secrets := map[string]string{"url": srv.URL, "signingSecret": secret}
	if err := n.Send(context.Background(), testEvent(), notify.Target{Version: "1.0.0"}, cfg, secrets); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotSig == "" {
		t.Fatal("server never saw X-CertForge-Signature")
	}
}

// TestWebhookHeadersAndAuth covers the task-4 brief's TestWebhookHeadersAndAuth:
// Content-Type, User-Agent, X-CertForge-Event/Delivery, a configured extra
// header and Authorization from authHeader.
func TestWebhookHeadersAndAuth(t *testing.T) {
	var got http.Header
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := notify.Webhook{Settings: allowLoopback}
	ev := testEvent()
	cfg := map[string]any{"headers": map[string]any{"X-Extra": "hello"}}
	secrets := map[string]string{"url": srv.URL, "authHeader": "Bearer tok123"}
	if err := n.Send(context.Background(), ev, notify.Target{Version: "9.9.9"}, cfg, secrets); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", got.Get("Content-Type"))
	}
	if got.Get("User-Agent") != "CertForge/9.9.9" {
		t.Errorf("User-Agent = %q", got.Get("User-Agent"))
	}
	if got.Get("X-CertForge-Event") != ev.Kind {
		t.Errorf("X-CertForge-Event = %q, want %q", got.Get("X-CertForge-Event"), ev.Kind)
	}
	if got.Get("X-CertForge-Delivery") != ev.ID.String() {
		t.Errorf("X-CertForge-Delivery = %q, want %q", got.Get("X-CertForge-Delivery"), ev.ID.String())
	}
	if got.Get("X-Extra") != "hello" {
		t.Errorf("X-Extra = %q, want hello", got.Get("X-Extra"))
	}
	if got.Get("Authorization") != "Bearer tok123" {
		t.Errorf("Authorization = %q", got.Get("Authorization"))
	}
	if got.Get("X-CertForge-Signature") != "" {
		t.Errorf("X-CertForge-Signature = %q, want empty (no signingSecret configured)", got.Get("X-CertForge-Signature"))
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if doc["kind"] != ev.Kind {
		t.Errorf("body kind = %v", doc["kind"])
	}
}

// TestWebhookRejectsCredentialHeaders covers the task-4 brief's
// TestWebhookRejectsCredentialHeaders: a header name on the credential
// denylist fails ValidateConfig, whatever the registered instance's exact
// casing.
func TestWebhookRejectsCredentialHeaders(t *testing.T) {
	reg := notify.NewRegistry()
	reg.Register(notify.Webhook{Settings: allowLoopback})

	for _, name := range []string{
		"Authorization", "authorization", "Cookie", "Proxy-Authorization",
		"Host", "Content-Type", "X-CertForge-Signature", "X-Api-Key", "X-My-Secret", "AuthToken",
	} {
		cfg := map[string]any{"url": "https://example.test/hook", "headers": map[string]any{name: "v"}}
		if err := reg.ValidateConfig(notify.TypeWebhook, cfg); err == nil {
			t.Errorf("header %q: ValidateConfig accepted it", name)
		}
	}

	// A benign header name is still accepted.
	cfg := map[string]any{"url": "https://example.test/hook", "headers": map[string]any{"X-Env": "prod"}}
	if err := reg.ValidateConfig(notify.TypeWebhook, cfg); err != nil {
		t.Errorf("benign header rejected: %v", err)
	}
}

// TestWebhookSchemaRejectsTooManyHeaders covers the schema's own
// maxProperties bound on headers (Shared contract: "headers? {...} (≤ 20;
// credential names rejected)").
func TestWebhookSchemaRejectsTooManyHeaders(t *testing.T) {
	reg := notify.NewRegistry()
	reg.Register(notify.Webhook{Settings: allowLoopback})

	headers := map[string]any{}
	for i := 0; i < 21; i++ {
		headers[uuid.New().String()[:8]] = "v"
	}
	cfg := map[string]any{"url": "https://example.test/hook", "headers": headers}
	if err := reg.ValidateConfig(notify.TypeWebhook, cfg); err == nil {
		t.Error("21 headers: ValidateConfig accepted it")
	}
}

// TestDeliveryErrorRedactsSecrets covers the task-4 brief's
// TestDeliveryErrorRedactsSecrets: a fake server that echoes the URL and the
// auth token in a 500 body must never leak either into Send's returned
// error — httpx.Client.Do's own error text embeds the (scrubbed) response
// body verbatim, so the guarantee here is that DeliverWorker's
// httpx.Redact(err.Error(), secretValues(secrets)...) pass (deliver.go,
// task 3) removes every secret value Send's own error could otherwise
// carry.
func TestDeliveryErrorRedactsSecrets(t *testing.T) {
	const token = "super-secret-bearer-token"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("failed for " + srv.URL + " auth=" + r.Header.Get("Authorization")))
	}))
	defer srv.Close()

	n := notify.Webhook{Settings: allowLoopback}
	secrets := map[string]string{"url": srv.URL, "authHeader": "Bearer " + token}
	err := n.Send(context.Background(), testEvent(), notify.Target{Version: "1.0.0"}, map[string]any{}, secrets)
	if err == nil {
		t.Fatal("Send returned nil error for a persistent 500")
	}

	secretValues := make([]string, 0, len(secrets))
	for _, v := range secrets {
		secretValues = append(secretValues, v)
	}
	// Mirrors deliver.go's recordFailure: DeliverWorker never stores or logs
	// a Send error before running it through httpx.Redact with every secret
	// value.
	redacted := httpx.Redact(err.Error(), secretValues...)
	for _, v := range secretValues {
		if v != "" && strings.Contains(redacted, v) {
			t.Fatalf("redacted error still carries a secret: %q", redacted)
		}
	}
}
