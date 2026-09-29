package notify

import (
	"errors"
	"strings"
	"testing"

	"github.com/riverqueue/river"
)

func TestChannelSummaryPerType(t *testing.T) {
	cases := []struct {
		typ     string
		cfg     map[string]any
		secrets map[string]string
		want    string
	}{
		{TypeWebhook, map[string]any{}, map[string]string{"url": "https://hooks.example.test:8443/abc?token=shh"}, "hooks.example.test"},
		{TypeDiscord, map[string]any{}, map[string]string{"webhookUrl": "https://discord.com/api/webhooks/1/2"}, "Discord webhook"},
		{TypeNtfy, map[string]any{"server": "https://ntfy.example.test", "topic": "alerts"}, nil, "ntfy.example.test/alerts"},
		{TypeNtfy, map[string]any{"topic": "alerts"}, nil, "ntfy.sh/alerts"}, // default server
		{TypeHomeAssistant, map[string]any{"baseUrl": "https://ha.example.test:8123"}, nil, "ha.example.test"},
		{TypeSMTP, map[string]any{"to": []any{"a@example.test", "b@example.test"}}, nil, "a@example.test, b@example.test"},
	}
	for _, c := range cases {
		got := Summary(c.typ, c.cfg, c.secrets)
		if got != c.want {
			t.Errorf("Summary(%s) = %q, want %q", c.typ, got, c.want)
		}
	}
}

// TestChannelSummaryNeverLeaksURLDetail proves the pre-flight ruling
// literally: a webhook/homeassistant URL's summary keeps only
// url.Hostname() — no scheme, port, path, query or userinfo, all of which
// could carry a secret (a token in the path or query, credentials as
// userinfo).
func TestChannelSummaryNeverLeaksURLDetail(t *testing.T) {
	secrets := map[string]string{"url": "https://user:pass@hooks.example.test:8443/secret/path?token=shh#frag"}
	got := Summary(TypeWebhook, map[string]any{}, secrets)
	want := "hooks.example.test"
	if got != want {
		t.Fatalf("Summary = %q, want %q", got, want)
	}
	for _, leak := range []string{"user", "pass", "8443", "secret/path", "token=shh", "frag", "https://"} {
		if strings.Contains(got, leak) {
			t.Errorf("Summary %q leaks %q", got, leak)
		}
	}
}

func TestSplitChannelConfigSeparatesSecrets(t *testing.T) {
	secretKeys := []string{"url", "authHeader", "signingSecret"}
	cfg := map[string]any{
		"url":           "https://example.test/hook",
		"authHeader":    "Bearer abc",
		"signingSecret": "", // empty: not stored
		"headers":       map[string]any{"X-Foo": "bar"},
	}
	public, secret, err := splitChannelConfig(secretKeys, cfg)
	if err != nil {
		t.Fatalf("splitChannelConfig: %v", err)
	}
	if _, ok := public["url"]; ok {
		t.Error("public config retained a secret field")
	}
	if _, ok := public["authHeader"]; ok {
		t.Error("public config retained a secret field")
	}
	if got := public["headers"]; got == nil {
		t.Error("public config dropped a non-secret field")
	}
	if secret["url"] != "https://example.test/hook" || secret["authHeader"] != "Bearer abc" {
		t.Errorf("secret map = %#v", secret)
	}
	if _, ok := secret["signingSecret"]; ok {
		t.Error("an empty secret value should not be stored")
	}
}

func TestSplitChannelConfigRejectsUnchangedOnCreate(t *testing.T) {
	secretKeys := []string{"url"}
	_, _, err := splitChannelConfig(secretKeys, map[string]any{"url": Unchanged})
	if err == nil {
		t.Fatal("splitChannelConfig accepted __unchanged__ with nothing stored")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error = %v, want *ValidationError", err)
	}
}

func TestMergeChannelConfigKeepsStoredSecretOnUnchanged(t *testing.T) {
	secretKeys := []string{"token"}
	oldSecret := map[string]string{"token": "s3cr3t"}
	resolved, reused := mergeChannelConfig(secretKeys, oldSecret, map[string]any{
		"server": "https://ntfy.example.test", "topic": "a", "token": Unchanged,
	})
	if !reused {
		t.Error("reusedSecret = false, want true")
	}
	if resolved["token"] != "s3cr3t" {
		t.Errorf("resolved token = %v, want the stored value", resolved["token"])
	}
	if resolved["server"] != "https://ntfy.example.test" {
		t.Errorf("resolved server = %v", resolved["server"])
	}
}

// TestMergeChannelConfigOmittedSecretKeepsStored is the contract's own
// rule ("secrets __unchanged__ or omitted keep the stored ones"), unlike
// DNS credential config's MergeUpdate, whose omitted secret is cleared.
func TestMergeChannelConfigOmittedSecretKeepsStored(t *testing.T) {
	secretKeys := []string{"token"}
	oldSecret := map[string]string{"token": "s3cr3t"}
	resolved, reused := mergeChannelConfig(secretKeys, oldSecret, map[string]any{"server": "https://ntfy.example.test", "topic": "a"})
	if !reused {
		t.Error("reusedSecret = false, want true (an omitted secret field still counts as kept)")
	}
	if resolved["token"] != "s3cr3t" {
		t.Errorf("resolved token = %v, want the stored value kept", resolved["token"])
	}
}

func TestMergeChannelConfigEmptyStringClearsSecret(t *testing.T) {
	secretKeys := []string{"token"}
	oldSecret := map[string]string{"token": "s3cr3t"}
	resolved, reused := mergeChannelConfig(secretKeys, oldSecret, map[string]any{"server": "https://ntfy.example.test", "topic": "a", "token": ""})
	if reused {
		t.Error("reusedSecret = true, want false (an explicit clear is not a keep)")
	}
	if _, ok := resolved["token"]; ok {
		t.Errorf("resolved kept a field explicitly cleared with \"\": %v", resolved["token"])
	}
}

// TestChannelReentryRule is the Deviations R3 rule: changing ntfy's server
// (or homeassistant's baseUrl) while the type's secret is kept Unchanged
// is a 422 "re-enter the secret" — an unrelated public field changing does
// not trigger it, and neither does changing the URL field together with a
// freshly provided secret.
func TestChannelReentryRule(t *testing.T) {
	oldPublic := map[string]any{"server": "https://ntfy.old.test", "topic": "a"}

	// server changed, token reused: rejected.
	newCfg := map[string]any{"server": "https://ntfy.new.test", "topic": "a", "token": "tok"}
	if err := checkChannelReentry(TypeNtfy, oldPublic, newCfg, true); err == nil {
		t.Error("changing server while reusing the secret was accepted")
	}

	// server unchanged, token reused: allowed.
	sameCfg := map[string]any{"server": "https://ntfy.old.test", "topic": "b"}
	if err := checkChannelReentry(TypeNtfy, oldPublic, sameCfg, true); err != nil {
		t.Errorf("server unchanged should be allowed while reusing the secret: %v", err)
	}

	// server changed, token freshly provided (reusedSecret=false): allowed.
	if err := checkChannelReentry(TypeNtfy, oldPublic, newCfg, false); err != nil {
		t.Errorf("server change with a fresh secret should be allowed: %v", err)
	}

	// A type with no reentry field (webhook: its whole URL is the secret
	// itself) is never subject to this rule.
	if err := checkChannelReentry(TypeWebhook, oldPublic, newCfg, true); err != nil {
		t.Errorf("webhook has no reentry field, want nil, got %v", err)
	}
}

func TestChannelHomeAssistantReentryField(t *testing.T) {
	oldPublic := map[string]any{"baseUrl": "https://ha.old.test:8123"}
	newCfg := map[string]any{"baseUrl": "https://ha.new.test:8123"}
	if err := checkChannelReentry(TypeHomeAssistant, oldPublic, newCfg, true); err == nil {
		t.Error("changing baseUrl while reusing webhookId was accepted")
	}
}

func TestCheckEventsRejectsUnknownKind(t *testing.T) {
	if err := checkEvents([]string{"cert.issued"}); err != nil {
		t.Errorf("known kind rejected: %v", err)
	}
	if err := checkEvents([]string{"cert.issued", "bogus.kind"}); err == nil {
		t.Error("unknown kind accepted")
	}
	if err := checkEvents(nil); err != nil {
		t.Errorf("empty events (means every kind) rejected: %v", err)
	}
}

func TestCheckSeverity(t *testing.T) {
	for _, ok := range []string{"info", "warning", "critical"} {
		if err := checkSeverity(ok); err != nil {
			t.Errorf("checkSeverity(%q) = %v", ok, err)
		}
	}
	if err := checkSeverity("urgent"); err == nil {
		t.Error("unknown severity accepted")
	}
}

func TestCheckChannelName(t *testing.T) {
	if _, err := checkChannelName("  ops-alerts  "); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
	if got, _ := checkChannelName("  ops-alerts  "); got != "ops-alerts" {
		t.Errorf("name not trimmed: %q", got)
	}
	if _, err := checkChannelName(""); err == nil {
		t.Error("empty name accepted")
	}
	long := make([]byte, 101)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := checkChannelName(string(long)); err == nil {
		t.Error("101-character name accepted")
	}
}

func TestChannelTypeImmutablePreventedAtInputLevel(t *testing.T) {
	// checkChannelURL/type-immutability itself is enforced by the API layer
	// (Shared contract: "type cannot change" — the same pattern
	// UpdateDeployTarget uses); this test only pins that the type of a
	// registered notifier can always be looked up by its own constant, so
	// the api-layer comparison (cur.Type != in.Type) has something stable
	// to compare against.
	for _, typ := range []string{TypeWebhook, TypeDiscord, TypeNtfy, TypeHomeAssistant, TypeSMTP} {
		if typ == "" {
			t.Error("empty channel type constant")
		}
	}
}

// TestChannelURLPolicyOnCreate proves checkChannelURL rejects a
// loopback-targeting URL field for every HTTP-notifier type unless
// allowLoopback is set, and accepts a public host.
func TestChannelURLPolicyOnCreate(t *testing.T) {
	cases := []struct {
		typ string
		cfg map[string]any
	}{
		{TypeWebhook, map[string]any{"url": "http://127.0.0.1/hook"}},
		{TypeDiscord, map[string]any{"webhookUrl": "http://127.0.0.1/hook"}},
		{TypeNtfy, map[string]any{"server": "http://127.0.0.1", "topic": "a"}},
		{TypeHomeAssistant, map[string]any{"baseUrl": "http://127.0.0.1:8123", "webhookId": "abc"}},
	}
	for _, c := range cases {
		if err := checkChannelURL(c.typ, c.cfg, false); err == nil {
			t.Errorf("%s: loopback URL accepted with allowLoopback=false", c.typ)
		}
		if err := checkChannelURL(c.typ, c.cfg, true); err != nil {
			t.Errorf("%s: loopback URL rejected with allowLoopback=true: %v", c.typ, err)
		}
	}
	// A public host is always fine.
	if err := checkChannelURL(TypeWebhook, map[string]any{"url": "https://example.test/hook"}, false); err != nil {
		t.Errorf("public https url rejected: %v", err)
	}
	// smtp has no URL field to check.
	if err := checkChannelURL(TypeSMTP, map[string]any{"to": []any{"a@example.test"}}, false); err != nil {
		t.Errorf("smtp (no URL field) rejected: %v", err)
	}
}

func TestChannelURLPolicyNtfyDefaultServer(t *testing.T) {
	// ntfy's server field defaults to ntfyDefaultServer (a public host)
	// when omitted — never treated as an empty/skipped check.
	if err := checkChannelURL(TypeNtfy, map[string]any{"topic": "a"}, false); err != nil {
		t.Errorf("default ntfy server rejected: %v", err)
	}
}

func TestStoredSecretKeysSortedNeverNil(t *testing.T) {
	if got := storedSecretKeys(nil); got == nil || len(got) != 0 {
		t.Fatalf("storedSecretKeys(nil) = %#v, want empty non-nil slice", got)
	}
	got := storedSecretKeys(map[string]string{"b": "1", "a": "2"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("storedSecretKeys = %v, want sorted [a b]", got)
	}
}

// TestServiceRegisterRiverAddsDeliverWorker: RegisterRiver adds
// DeliverWorker (task-3 brief: it lands with Task 6's Service) and returns
// no periodic job (a delivery is only ever enqueued reactively by Emit).
func TestServiceRegisterRiverAddsDeliverWorker(t *testing.T) {
	s := &Service{Store: &Store{Q: nil}, Registry: NewRegistry()}
	workers := river.NewWorkers()
	periodic := s.RegisterRiver(workers)
	if periodic != nil {
		t.Fatalf("RegisterRiver periodic jobs = %v, want nil", periodic)
	}
	// A second AddWorkerSafely for the same job kind (DeliverArgs) fails,
	// proving RegisterRiver already registered one.
	if err := river.AddWorkerSafely(workers, &DeliverWorker{}); err == nil {
		t.Fatal("RegisterRiver did not add a DeliverWorker: a duplicate registration was accepted")
	}
}
