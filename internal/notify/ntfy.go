package notify

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/metril/certforge/internal/notify/httpx"
)

// TypeNtfy is the ntfy channel type (Shared contract: ChannelType).
const TypeNtfy = "ntfy"

//go:embed ntfy.schema.json
var ntfySchema []byte

// ntfyDefaultServer is the schema's own default (Shared contract: "server
// (uri, default https://ntfy.sh)"), used when a channel's cfg omits it.
const ntfyDefaultServer = "https://ntfy.sh"

// ntfyTitleLimit bounds the Title header (Shared contract: "≤ 200").
const ntfyTitleLimit = 200

// ntfyPriorityBySeverity maps Severity to ntfy's numeric priority (Shared
// contract, Wire formats row).
var ntfyPriorityBySeverity = map[string]string{
	"info":     "3",
	"warning":  "4",
	"critical": "5",
}

// Ntfy is the "ntfy" HTTP notifier: a push notification published through
// ntfy.sh or a self-hosted ntfy server (Shared contract: notifier configs,
// wire formats).
type Ntfy struct {
	// Settings reads the live "notifications" section at Send time — see
	// dialOptions (webhook.go).
	Settings SettingsFunc
}

// Type returns TypeNtfy.
func (Ntfy) Type() string { return TypeNtfy }

// Name is the type's GET /meta/schemas display name.
func (Ntfy) Name() string { return "ntfy" }

// Schema returns ntfy's config JSON Schema.
func (Ntfy) Schema() []byte { return ntfySchema }

// Send POSTs ev's summary as plain text to cfg's server/topic.
func (n Ntfy) Send(ctx context.Context, ev Event, target Target, cfg map[string]any, secrets map[string]string) error {
	server, _ := cfg["server"].(string)
	if server == "" {
		server = ntfyDefaultServer
	}
	topic, _ := cfg["topic"].(string)
	if topic == "" {
		return fmt.Errorf("notify: ntfy: topic is not configured")
	}
	dest := strings.TrimRight(server, "/") + "/" + topic

	opts, err := dialOptions(ctx, n.Settings, cfg)
	if err != nil {
		return fmt.Errorf("notify: ntfy: %w", err)
	}
	if err := httpx.CheckURL(dest, opts.AllowLoopback); err != nil {
		return fmt.Errorf("notify: ntfy: %w", err)
	}
	client, err := httpx.New(opts)
	if err != nil {
		return fmt.Errorf("notify: ntfy: %w", err)
	}

	title := "CertForge"
	if target.OrgName != "" {
		title = "CertForge — " + target.OrgName
	}
	title = truncate(stripCRLFAndControl(title), ntfyTitleLimit)

	h := http.Header{}
	h.Set("Title", title)
	h.Set("Priority", ntfyPriorityBySeverity[ev.Severity])
	h.Set("X-Tags", ev.Severity+","+strings.ReplaceAll(ev.Kind, ".", "_"))
	if token := secrets["token"]; token != "" {
		h.Set("Authorization", "Bearer "+token)
	}

	if _, err := client.Do(ctx, http.MethodPost, dest, h, []byte(ev.Summary)); err != nil {
		return fmt.Errorf("notify: ntfy: %w", err)
	}
	return nil
}

// stripCRLFAndControl removes CR/LF and every other non-printable character
// from an ntfy Title header value (Shared contract: "strips CR/LF and
// non-printable characters from Title"), so a crafted event summary or org
// name can never inject an extra header line.
func stripCRLFAndControl(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\r' || r == '\n' || !unicode.IsPrint(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
