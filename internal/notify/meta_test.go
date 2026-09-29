package notify_test

import (
	"testing"

	"github.com/metril/certforge/internal/meta"
	"github.com/metril/certforge/internal/notify"
)

// TestMetaListsNotifiers covers the task-4 brief's TestMetaListsNotifiers:
// AddToMeta lists every registered notifier under meta.KindNotifier with
// the Shared contract's own type code and display name. Task 4 registers
// the four HTTP notifier types; smtp (the ChannelType enum's fifth value)
// is registered by Task 5, so this Registry — and this test — holds four
// entries, not the eventual five.
func TestMetaListsNotifiers(t *testing.T) {
	reg := notify.NewRegistry()
	reg.Register(notify.Webhook{Settings: allowLoopback})
	reg.Register(notify.Discord{Settings: allowLoopback})
	reg.Register(notify.Ntfy{Settings: allowLoopback})
	reg.Register(notify.HomeAssistant{Settings: allowLoopback})

	metaReg := meta.NewRegistry()
	notify.AddToMeta(reg, metaReg)

	entries := metaReg.List(meta.KindNotifier)
	if len(entries) != 4 {
		t.Fatalf("entries = %d, want 4: %+v", len(entries), entries)
	}

	want := map[string]string{
		notify.TypeWebhook:       "Webhook",
		notify.TypeDiscord:       "Discord",
		notify.TypeNtfy:          "ntfy",
		notify.TypeHomeAssistant: "Home Assistant",
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Code] = e.Name
		if len(e.Schema) == 0 || string(e.Schema) == "null" {
			t.Errorf("%s: empty schema", e.Code)
		}
	}
	for code, name := range want {
		if got[code] != name {
			t.Errorf("code %q: name = %q, want %q", code, got[code], name)
		}
	}
}
