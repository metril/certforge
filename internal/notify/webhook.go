package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/metril/certforge/internal/notify/httpx"
)

// TypeWebhook is the webhook channel type (Shared contract: ChannelType).
const TypeWebhook = "webhook"

//go:embed webhook.schema.json
var webhookSchema []byte

// deniedHeaderNames are exact (case-insensitive) header names CheckConfig
// rejects outright: a credential (Authorization, Cookie,
// Proxy-Authorization), the dial-time Host, and the body's own
// Content-Type (Deviations R3/R10).
var deniedHeaderNames = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"proxy-authorization": true,
	"host":                true,
	"content-type":        true,
}

// deniedHeaderSubstrings are lowercase substrings that make a header name
// look like it carries a credential, whatever it is actually called
// (Deviations R3: "any name containing token, key, secret or auth").
var deniedHeaderSubstrings = []string{"token", "key", "secret", "auth"}

// checkHeaderName rejects a header name on the credential denylist
// (Deviations R3). name has already matched the schema's
// patternProperties pattern by the time this runs.
func checkHeaderName(name string) error {
	lower := strings.ToLower(name)
	if deniedHeaderNames[lower] || strings.HasPrefix(lower, "x-certforge-") {
		return fmt.Errorf("notify: webhook: header %q is not allowed", name)
	}
	for _, sub := range deniedHeaderSubstrings {
		if strings.Contains(lower, sub) {
			return fmt.Errorf("notify: webhook: header %q is not allowed", name)
		}
	}
	return nil
}

// SettingsFunc reads the live "notifications" settings section
// (allowLoopbackUrls) at Send time — never cached by a Notifier itself,
// since an operator can flip the policy at any moment and Send must see the
// change on its very next attempt (task-4 brief: "the live
// notifications.allowLoopbackUrls"). Production wires a closure over
// notify.Current and a real *settings.Store (cmd/certforge/serve.go); a
// test supplies a fixed value with no store at all — the settings.Store the
// real Current reads through needs a live database, which an httptest-based
// notifier test has no reason to stand up.
type SettingsFunc func(ctx context.Context) (Settings, error)

// dialOptions builds httpx.Options for a Send call: cfg's own caPem, plus
// settingsFn's live allowLoopbackUrls — shared by every HTTP notifier in
// this package.
func dialOptions(ctx context.Context, settingsFn SettingsFunc, cfg map[string]any) (httpx.Options, error) {
	s, err := settingsFn(ctx)
	if err != nil {
		return httpx.Options{}, fmt.Errorf("read notifications settings: %w", err)
	}
	caPem, _ := cfg["caPem"].(string)
	return httpx.Options{CAPEM: caPem, AllowLoopback: s.AllowLoopbackURLs}, nil
}

// Webhook is the "webhook" HTTP notifier: a JSON POST to any URL, optionally
// HMAC-signed and with extra headers (Shared contract: notifier configs,
// wire formats).
type Webhook struct {
	// Settings reads the live "notifications" section at Send time — see
	// SettingsFunc/dialOptions.
	Settings SettingsFunc
}

// Type returns TypeWebhook.
func (Webhook) Type() string { return TypeWebhook }

// Name is the type's GET /meta/schemas display name.
func (Webhook) Name() string { return "Webhook" }

// Schema returns webhook's config JSON Schema.
func (Webhook) Schema() []byte { return webhookSchema }

// CheckConfig rejects a header whose name looks like it carries a
// credential (ValidateConfig's extra check beyond the JSON Schema).
func (Webhook) CheckConfig(cfg map[string]any) error {
	headers, _ := cfg["headers"].(map[string]any)
	for name := range headers {
		if err := checkHeaderName(name); err != nil {
			return err
		}
	}
	return nil
}

// Send POSTs ev's payload to cfg's url, signing the exact bytes sent when a
// signingSecret is configured.
func (n Webhook) Send(ctx context.Context, ev Event, target Target, cfg map[string]any, secrets map[string]string) error {
	url := secrets["url"]
	if url == "" {
		return fmt.Errorf("notify: webhook: url is not configured")
	}

	opts, err := dialOptions(ctx, n.Settings, cfg)
	if err != nil {
		return fmt.Errorf("notify: webhook: %w", err)
	}
	if err := httpx.CheckURL(url, opts.AllowLoopback); err != nil {
		return fmt.Errorf("notify: webhook: %w", err)
	}
	client, err := httpx.New(opts)
	if err != nil {
		return fmt.Errorf("notify: webhook: %w", err)
	}

	body := Payload(ev, target)

	h := http.Header{}
	if headers, ok := cfg["headers"].(map[string]any); ok {
		for name, v := range headers {
			if s, ok := v.(string); ok {
				h.Set(name, s)
			}
		}
	}
	// Set after the configured extras so nothing a channel's own headers
	// map holds (already denylisted at CheckConfig time, but defense in
	// depth) can shadow one of these.
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", "CertForge/"+target.Version)
	h.Set("X-CertForge-Event", ev.Kind)
	h.Set("X-CertForge-Delivery", ev.ID.String())
	if secret := secrets["signingSecret"]; secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		h.Set("X-CertForge-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		// V2 binds a timestamp into the MAC so a captured request cannot be
		// replayed outside the receiver's freshness window. V1 stays for
		// receivers that have not moved over.
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac2 := hmac.New(sha256.New, []byte(secret))
		mac2.Write([]byte(ts + "."))
		mac2.Write(body)
		h.Set("X-CertForge-Timestamp", ts)
		h.Set("X-CertForge-Signature-V2", "sha256="+hex.EncodeToString(mac2.Sum(nil)))
	}
	if auth := secrets["authHeader"]; auth != "" {
		h.Set("Authorization", auth)
	}

	if _, err := client.Do(ctx, http.MethodPost, url, h, body); err != nil {
		return fmt.Errorf("notify: webhook: %w", err)
	}
	return nil
}
