package notify_test

import (
	"context"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/meta"
	"github.com/metril/certforge/internal/notify"
)

// TestSMTPRegisteredInMeta covers AddToMeta once "smtp" is registered
// alongside the task-4 HTTP notifiers (meta_test.go's own
// TestMetaListsNotifiers stays scoped to those four by design — see its
// doc comment — so this is a separate, additive check rather than an edit
// to that file).
func TestSMTPRegisteredInMeta(t *testing.T) {
	reg := notify.NewRegistry()
	reg.Register(notify.SMTP{Settings: func(context.Context) (notify.SMTPSettings, string, error) {
		return notify.SMTPSettings{}, "", nil
	}})
	metaReg := meta.NewRegistry()
	notify.AddToMeta(reg, metaReg)

	entries := metaReg.List(meta.KindNotifier)
	if len(entries) != 1 || entries[0].Code != notify.TypeSMTP || entries[0].Name != "Email" {
		t.Fatalf("entries = %+v, want one {smtp Email}", entries)
	}
	if len(entries[0].Schema) == 0 || string(entries[0].Schema) == "null" {
		t.Errorf("empty schema")
	}
}

// TestSMTPNotifierUnconfigured covers the contract: Send fails with "SMTP
// is not configured" when the live "smtp" settings section's host is
// empty, without attempting to dial anything.
func TestSMTPNotifierUnconfigured(t *testing.T) {
	n := notify.SMTP{Settings: func(context.Context) (notify.SMTPSettings, string, error) {
		return notify.SMTPSettings{}, "", nil
	}}
	err := n.Send(context.Background(), notify.Event{Kind: "test", Summary: "hi"}, notify.Target{},
		map[string]any{"to": []any{"a@example.test"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "SMTP is not configured") {
		t.Fatalf("err = %v, want \"SMTP is not configured\"", err)
	}
}

// TestSMTPNotifierSendsToConfiguredRecipients covers the smtp notifier's
// own wiring: it reads recipients and a subject prefix from the channel's
// cfg (not the global settings section) and delivers through the live
// global "smtp" section.
func TestSMTPNotifierSendsToConfiguredRecipients(t *testing.T) {
	srv := startFakeSMTP(t, fakeSMTPOptions{})
	host, port := splitAddr(t, srv.Addr())

	n := notify.SMTP{Settings: func(context.Context) (notify.SMTPSettings, string, error) {
		return notify.SMTPSettings{Host: host, Port: port, From: "certforge@example.test", Security: "none", TimeoutSeconds: 5}, "", nil
	}}
	ev := notify.Event{Kind: "cert.expiring", Summary: "example.com expires in 7 days", Severity: "warning",
		Resource: notify.Resource{Type: "certificate", ID: "1", Name: "example.com"}}
	cfg := map[string]any{"to": []any{"ops@example.test", "sec@example.test"}, "subjectPrefix": "[Alert]"}

	if err := n.Send(context.Background(), ev, notify.Target{}, cfg, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}

	msgs := srv.Messages()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d, want 1", len(msgs))
	}
	if len(msgs[0].To) != 2 {
		t.Fatalf("to = %v, want 2 recipients", msgs[0].To)
	}
	if !strings.Contains(msgs[0].Data, "Subject: [Alert] example.com expires in 7 days") {
		t.Fatalf("subject: %q", msgs[0].Data)
	}
	if !strings.Contains(msgs[0].Data, "Kind: cert.expiring") || !strings.Contains(msgs[0].Data, "Severity: warning") {
		t.Fatalf("body missing kind/severity: %q", msgs[0].Data)
	}
}
