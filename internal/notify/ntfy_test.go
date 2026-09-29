package notify_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/metril/certforge/internal/notify"
)

// TestNtfyHeaders covers the task-4 brief's TestNtfyHeaders: priority,
// tags, bearer and CR/LF stripped from Title.
func TestNtfyHeaders(t *testing.T) {
	var got http.Header
	var path string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		path = r.URL.Path
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := notify.Ntfy{Settings: allowLoopback}
	ev := testEvent()
	ev.Severity = "critical"
	cfg := map[string]any{"server": srv.URL, "topic": "certforge-alerts"}
	secrets := map[string]string{"token": "tk_abc123"}
	target := notify.Target{OrgName: "Acme\r\nInjected: yes"}
	if err := n.Send(context.Background(), ev, target, cfg, secrets); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if path != "/certforge-alerts" {
		t.Errorf("path = %q, want /certforge-alerts", path)
	}
	if got.Get("Priority") != "5" {
		t.Errorf("Priority = %q, want 5 for critical", got.Get("Priority"))
	}
	if got.Get("X-Tags") != "critical,cert_expiring" {
		t.Errorf("X-Tags = %q, want critical,cert_expiring", got.Get("X-Tags"))
	}
	if got.Get("Authorization") != "Bearer tk_abc123" {
		t.Errorf("Authorization = %q", got.Get("Authorization"))
	}
	title := got.Get("Title")
	if title == "" {
		t.Fatal("Title is empty")
	}
	for _, r := range title {
		if r == '\r' || r == '\n' {
			t.Fatalf("Title still carries CR/LF: %q", title)
		}
	}
	if string(body) != ev.Summary {
		t.Errorf("body = %q, want the event summary %q", body, ev.Summary)
	}
}

// TestNtfyDefaultServer covers ntfy's own default server when a channel's
// cfg omits it: the schema does not require "server" (Shared contract:
// "server (uri, default https://ntfy.sh)"), and Send falls back to
// ntfyDefaultServer for a dial target — checked here through
// ValidateConfig's schema pass, since a live Send to the real ntfy.sh would
// make this test depend on the network.
func TestNtfyDefaultServer(t *testing.T) {
	reg := notify.NewRegistry()
	reg.Register(notify.Ntfy{Settings: allowLoopback})
	if err := reg.ValidateConfig(notify.TypeNtfy, map[string]any{"topic": "certforge-alerts"}); err != nil {
		t.Errorf("topic-only config (server defaults) rejected: %v", err)
	}
}

// TestNtfyPriorityBySeverity covers info/warning priorities.
func TestNtfyPriorityBySeverity(t *testing.T) {
	cases := map[string]string{"info": "3", "warning": "4"}
	for severity, want := range cases {
		var got string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("Priority")
			w.WriteHeader(http.StatusOK)
		}))

		n := notify.Ntfy{Settings: allowLoopback}
		ev := testEvent()
		ev.Severity = severity
		cfg := map[string]any{"server": srv.URL, "topic": "t"}
		if err := n.Send(context.Background(), ev, notify.Target{}, cfg, nil); err != nil {
			t.Fatalf("%s: Send: %v", severity, err)
		}
		srv.Close()
		if got != want {
			t.Errorf("%s: Priority = %q, want %q", severity, got, want)
		}
	}
}
