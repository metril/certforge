package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/metril/certforge/internal/notify"
)

// TestHomeAssistantPath covers the task-4 brief's TestHomeAssistantPath:
// baseUrl and /api/webhook/<id> join without a double slash, and the body
// is the Webhook payload shape.
func TestHomeAssistantPath(t *testing.T) {
	var path string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := notify.HomeAssistant{Settings: allowLoopback}
	ev := testEvent()
	cfg := map[string]any{"baseUrl": srv.URL + "/"} // trailing slash: must not produce //api
	secrets := map[string]string{"webhookId": "my_webhook-ID123"}
	if err := n.Send(context.Background(), ev, notify.Target{}, cfg, secrets); err != nil {
		t.Fatalf("Send: %v", err)
	}

	want := "/api/webhook/" + secrets["webhookId"]
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if doc["kind"] != ev.Kind {
		t.Errorf("body kind = %v, want %v", doc["kind"], ev.Kind)
	}
	if doc["summary"] != ev.Summary {
		t.Errorf("body summary = %v", doc["summary"])
	}
}

// TestHomeAssistantPathNoTrailingSlash covers a baseUrl with no trailing
// slash (the common case): still no double slash.
func TestHomeAssistantPathNoTrailingSlash(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := notify.HomeAssistant{Settings: allowLoopback}
	cfg := map[string]any{"baseUrl": srv.URL}
	secrets := map[string]string{"webhookId": "abc123"}
	if err := n.Send(context.Background(), testEvent(), notify.Target{}, cfg, secrets); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if path != "/api/webhook/abc123" {
		t.Errorf("path = %q", path)
	}
}

// TestHomeAssistantCheckConfigRejectsBadWebhookID covers ValidateConfig's
// homeassistant-only extra check: webhookId's character set, since Send
// concatenates it directly into the request path.
func TestHomeAssistantCheckConfigRejectsBadWebhookID(t *testing.T) {
	reg := notify.NewRegistry()
	reg.Register(notify.HomeAssistant{Settings: allowLoopback})

	for _, id := range []string{"has a space", "slash/injected", "../escape", ""} {
		cfg := map[string]any{"baseUrl": "https://ha.example.test", "webhookId": id}
		if err := reg.ValidateConfig(notify.TypeHomeAssistant, cfg); err == nil {
			t.Errorf("webhookId %q: ValidateConfig accepted it", id)
		}
	}
	cfg := map[string]any{"baseUrl": "https://ha.example.test", "webhookId": "valid_ID-123"}
	if err := reg.ValidateConfig(notify.TypeHomeAssistant, cfg); err != nil {
		t.Errorf("valid webhookId rejected: %v", err)
	}
}
