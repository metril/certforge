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

// TestDiscordEmbedShape covers the task-4 brief's TestDiscordEmbedShape:
// colour per severity and no mentions, plus the rest of the embed's shape
// (username, timestamp, fields, footer).
func TestDiscordEmbedShape(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := notify.Discord{Settings: allowLoopback}
	ev := testEvent()
	ev.Severity = "critical"
	secrets := map[string]string{"webhookUrl": srv.URL}
	if err := n.Send(context.Background(), ev, notify.Target{OrgName: "Acme"}, map[string]any{}, secrets); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var doc struct {
		Username        string `json:"username"`
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
		Embeds []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Color       int    `json:"color"`
			Timestamp   string `json:"timestamp"`
			Fields      []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"fields"`
			Footer struct {
				Text string `json:"text"`
			} `json:"footer"`
		} `json:"embeds"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}

	if doc.Username != "CertForge" {
		t.Errorf("username = %q", doc.Username)
	}
	if doc.AllowedMentions.Parse == nil || len(doc.AllowedMentions.Parse) != 0 {
		t.Errorf("allowed_mentions.parse = %v, want []", doc.AllowedMentions.Parse)
	}
	if len(doc.Embeds) != 1 {
		t.Fatalf("embeds = %d, want 1", len(doc.Embeds))
	}
	embed := doc.Embeds[0]
	if embed.Title != ev.Summary {
		t.Errorf("title = %q, want %q", embed.Title, ev.Summary)
	}
	if embed.Color != 0xEF4444 {
		t.Errorf("color = %#x, want critical 0xEF4444", embed.Color)
	}
	if embed.Timestamp == "" {
		t.Error("timestamp is empty")
	}
	var haveKind, haveResource bool
	for _, f := range embed.Fields {
		switch f.Name {
		case "Kind":
			haveKind = f.Value == ev.Kind
		case "Resource":
			haveResource = f.Value != ""
		}
	}
	if !haveKind {
		t.Error("no Kind field with the event's kind")
	}
	if !haveResource {
		t.Error("no Resource field")
	}
	if embed.Footer.Text != "Acme" {
		t.Errorf("footer.text = %q, want Acme", embed.Footer.Text)
	}
}

// TestDiscordColorBySeverity covers the info/warning colours (critical is
// covered by TestDiscordEmbedShape).
func TestDiscordColorBySeverity(t *testing.T) {
	cases := map[string]int{"info": 0x3B82F6, "warning": 0xF59E0B}
	for severity, want := range cases {
		var body []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))

		n := notify.Discord{Settings: allowLoopback}
		ev := testEvent()
		ev.Severity = severity
		secrets := map[string]string{"webhookUrl": srv.URL}
		if err := n.Send(context.Background(), ev, notify.Target{}, map[string]any{}, secrets); err != nil {
			t.Fatalf("%s: Send: %v", severity, err)
		}
		srv.Close()

		var doc struct {
			Embeds []struct {
				Color int `json:"color"`
			} `json:"embeds"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("%s: body is not valid JSON: %v", severity, err)
		}
		if len(doc.Embeds) != 1 || doc.Embeds[0].Color != want {
			t.Errorf("%s: color = %#x, want %#x", severity, doc.Embeds[0].Color, want)
		}
	}
}

// TestDiscordGlobalEventHasNoFooter covers a global event (no org name to
// put in the footer).
func TestDiscordGlobalEventHasNoFooter(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := notify.Discord{Settings: allowLoopback}
	secrets := map[string]string{"webhookUrl": srv.URL}
	if err := n.Send(context.Background(), testEvent(), notify.Target{}, map[string]any{}, secrets); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var doc struct {
		Embeds []map[string]any `json:"embeds"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if _, present := doc.Embeds[0]["footer"]; present {
		t.Errorf("footer present for a global event: %v", doc.Embeds[0]["footer"])
	}
}

// TestDiscordCheckConfigRequiresHTTPS covers ValidateConfig's discord-only
// extra check: webhookUrl must be https.
func TestDiscordCheckConfigRequiresHTTPS(t *testing.T) {
	reg := notify.NewRegistry()
	reg.Register(notify.Discord{Settings: allowLoopback})

	if err := reg.ValidateConfig(notify.TypeDiscord, map[string]any{"webhookUrl": "http://discord.example/hook"}); err == nil {
		t.Error("http webhookUrl: ValidateConfig accepted it")
	}
	if err := reg.ValidateConfig(notify.TypeDiscord, map[string]any{"webhookUrl": "https://discord.example/hook"}); err != nil {
		t.Errorf("https webhookUrl rejected: %v", err)
	}
}
