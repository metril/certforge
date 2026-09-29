package notify

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/metril/certforge/internal/notify/httpx"
)

// TypeDiscord is the discord channel type (Shared contract: ChannelType).
const TypeDiscord = "discord"

//go:embed discord.schema.json
var discordSchema []byte

// discordTitleLimit and discordDescriptionLimit are Discord's own embed
// field limits (Shared contract, Wire formats row).
const (
	discordTitleLimit       = 256
	discordDescriptionLimit = 4096
)

// discordColorBySeverity are the embed side-bar colours (Shared contract,
// Wire formats row).
var discordColorBySeverity = map[string]int{
	"info":     0x3B82F6,
	"warning":  0xF59E0B,
	"critical": 0xEF4444,
}

// truncate returns s trimmed to at most max runes (never splitting a
// multi-byte one), for a Discord embed field or an ntfy Title that must
// stay within its platform's own limit.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// Discord is the "discord" HTTP notifier: one embed per event, posted
// through a Discord incoming webhook (Shared contract: notifier configs,
// wire formats).
type Discord struct {
	// Settings reads the live "notifications" section at Send time — see
	// dialOptions (webhook.go).
	Settings SettingsFunc
}

// Type returns TypeDiscord.
func (Discord) Type() string { return TypeDiscord }

// Name is the type's GET /meta/schemas display name.
func (Discord) Name() string { return "Discord" }

// Schema returns discord's config JSON Schema.
func (Discord) Schema() []byte { return discordSchema }

// CheckConfig rejects a webhookUrl that is not https (Shared contract:
// "webhookUrl🔒 (https)"; a Go check rather than a schema pattern since
// webhookUrl is secret — see ConfigChecker's doc comment).
func (Discord) CheckConfig(cfg map[string]any) error {
	raw, _ := cfg["webhookUrl"].(string)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("notify: discord: webhookUrl must be an https URL")
	}
	return nil
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Timestamp   string         `json:"timestamp"`
	Fields      []discordField `json:"fields"`
	Footer      *discordFooter `json:"footer,omitempty"`
}

type discordField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type discordFooter struct {
	Text string `json:"text"`
}

type discordMentions struct {
	Parse []string `json:"parse"`
}

type discordBody struct {
	Username        string          `json:"username"`
	AllowedMentions discordMentions `json:"allowed_mentions"`
	Embeds          []discordEmbed  `json:"embeds"`
}

// Send posts one embed for ev to cfg's webhookUrl.
func (n Discord) Send(ctx context.Context, ev Event, target Target, cfg map[string]any, secrets map[string]string) error {
	webhookURL := secrets["webhookUrl"]
	if webhookURL == "" {
		return fmt.Errorf("notify: discord: webhookUrl is not configured")
	}

	opts, err := dialOptions(ctx, n.Settings, cfg)
	if err != nil {
		return fmt.Errorf("notify: discord: %w", err)
	}
	if err := httpx.CheckURL(webhookURL, opts.AllowLoopback); err != nil {
		return fmt.Errorf("notify: discord: %w", err)
	}
	client, err := httpx.New(opts)
	if err != nil {
		return fmt.Errorf("notify: discord: %w", err)
	}

	embed := discordEmbed{
		Title:       truncate(ev.Summary, discordTitleLimit),
		Description: truncate(discordDetailLines(ev), discordDescriptionLimit),
		Color:       discordColorBySeverity[ev.Severity],
		Timestamp:   ev.At.UTC().Format(time.RFC3339),
		Fields: []discordField{
			{Name: "Kind", Value: ev.Kind},
			{Name: "Resource", Value: fmt.Sprintf("%s (%s)", ev.Resource.Name, ev.Resource.Type)},
		},
	}
	if target.OrgName != "" {
		embed.Footer = &discordFooter{Text: target.OrgName}
	}

	body, err := json.Marshal(discordBody{
		Username:        "CertForge",
		AllowedMentions: discordMentions{Parse: []string{}},
		Embeds:          []discordEmbed{embed},
	})
	if err != nil {
		return fmt.Errorf("notify: discord: encode body: %w", err)
	}

	h := http.Header{"Content-Type": {"application/json"}}
	if _, err := client.Do(ctx, http.MethodPost, webhookURL, h, body); err != nil {
		return fmt.Errorf("notify: discord: %w", err)
	}
	return nil
}

// discordDetailLines renders ev's allowlisted details as "key: value" lines,
// sorted by key, empty when there are none.
func discordDetailLines(ev Event) string {
	details := filterDetails(ev.Kind, ev.Details)
	if len(details) == 0 {
		return ""
	}
	keys := make([]string, 0, len(details))
	for k := range details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%s: %v", k, details[k]))
	}
	return strings.Join(lines, "\n")
}
