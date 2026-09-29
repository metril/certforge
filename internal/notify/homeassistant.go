package notify

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/metril/certforge/internal/notify/httpx"
)

// TypeHomeAssistant is the homeassistant channel type (Shared contract:
// ChannelType).
const TypeHomeAssistant = "homeassistant"

//go:embed homeassistant.schema.json
var homeAssistantSchema []byte

// webhookIDRe matches a Home Assistant webhookId (Shared contract:
// "webhookId🔒 ^[A-Za-z0-9_-]{1,128}$"); enforced here rather than the
// schema's pattern keyword since webhookId is secret (ConfigChecker's doc
// comment). Send checks against it again before the value is ever placed in
// a request path, since a channel row written before this check existed (or
// by anything other than ValidateConfig) is otherwise untrusted input.
var webhookIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// HomeAssistant is the "homeassistant" HTTP notifier: calls a Home
// Assistant webhook automation trigger with the Webhook payload body
// (Shared contract: notifier configs, wire formats).
type HomeAssistant struct {
	// Settings reads the live "notifications" section at Send time — see
	// dialOptions (webhook.go).
	Settings SettingsFunc
}

// Type returns TypeHomeAssistant.
func (HomeAssistant) Type() string { return TypeHomeAssistant }

// Name is the type's GET /meta/schemas display name.
func (HomeAssistant) Name() string { return "Home Assistant" }

// Schema returns homeassistant's config JSON Schema.
func (HomeAssistant) Schema() []byte { return homeAssistantSchema }

// CheckConfig rejects a webhookId outside its allowed character set: Send
// concatenates it straight into the request path, so anything else could
// escape it (Shared contract's pattern, enforced here rather than the
// schema — see ConfigChecker's doc comment).
func (HomeAssistant) CheckConfig(cfg map[string]any) error {
	id, _ := cfg["webhookId"].(string)
	if !webhookIDRe.MatchString(id) {
		return fmt.Errorf("notify: homeassistant: webhookId must match ^[A-Za-z0-9_-]{1,128}$")
	}
	return nil
}

// Send POSTs the Webhook payload body to cfg's baseUrl + /api/webhook/ +
// webhookId.
func (n HomeAssistant) Send(ctx context.Context, ev Event, target Target, cfg map[string]any, secrets map[string]string) error {
	baseURL, _ := cfg["baseUrl"].(string)
	webhookID := secrets["webhookId"]
	if baseURL == "" || webhookID == "" {
		return fmt.Errorf("notify: homeassistant: baseUrl and webhookId are required")
	}
	if !webhookIDRe.MatchString(webhookID) {
		return fmt.Errorf("notify: homeassistant: webhookId must match ^[A-Za-z0-9_-]{1,128}$")
	}
	dest := strings.TrimRight(baseURL, "/") + "/api/webhook/" + webhookID

	opts, err := dialOptions(ctx, n.Settings, cfg)
	if err != nil {
		return fmt.Errorf("notify: homeassistant: %w", err)
	}
	if err := httpx.CheckURL(dest, opts.AllowLoopback); err != nil {
		return fmt.Errorf("notify: homeassistant: %w", err)
	}
	client, err := httpx.New(opts)
	if err != nil {
		return fmt.Errorf("notify: homeassistant: %w", err)
	}

	body := Payload(ev, target)
	h := http.Header{"Content-Type": {"application/json"}}
	if _, err := client.Do(ctx, http.MethodPost, dest, h, body); err != nil {
		return fmt.Errorf("notify: homeassistant: %w", err)
	}
	return nil
}
