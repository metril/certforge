package notify

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/metril/certforge/internal/settings"
)

// TypeSMTP is the smtp channel type (Shared contract: ChannelType).
const TypeSMTP = "smtp"

//go:embed smtp.channel.schema.json
var smtpChannelSchema []byte

// smtpDefaultSubjectPrefix is the channel config schema's own default
// (smtp.channel.schema.json: "subjectPrefix" default "[CertForge]"), used
// when a channel's cfg omits it.
const smtpDefaultSubjectPrefix = "[CertForge]"

// SMTPSettingsFunc reads the live "smtp" settings section — its public
// fields and its decrypted password — at Send time. Never cached by a
// Notifier itself (SettingsFunc's doc comment, webhook.go): an operator
// can reconfigure the relay at any moment and Send must see the change on
// its very next attempt.
type SMTPSettingsFunc func(ctx context.Context) (SMTPSettings, string, error)

// CurrentSMTP reads the live "smtp" settings section through sections and
// store: SMTP's Settings field (cmd/certforge/serve.go) and
// testSmtpSettings (internal/api/settings.go) both call this rather than
// each duplicating GetSection plus SectionSecrets.
func CurrentSMTP(ctx context.Context, store *settings.Store, sections *settings.Registry) (SMTPSettings, string, error) {
	sec, ok := sections.Section(SMTPSectionName)
	if !ok {
		return SMTPSettings{}, "", fmt.Errorf("notify: %q settings section not registered", SMTPSectionName)
	}
	raw, _, err := store.GetSection(ctx, sec)
	if err != nil {
		return SMTPSettings{}, "", err
	}
	var s SMTPSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		return SMTPSettings{}, "", err
	}
	secrets, err := store.SectionSecrets(ctx, sec)
	if err != nil {
		return SMTPSettings{}, "", err
	}
	return s, secrets["password"], nil
}

// SMTP is the "smtp" notifier: emails ev's summary to the channel's
// recipients through the server configured in the global "smtp" settings
// section (Shared contract: notifier configs, wire formats). Unlike the
// HTTP notifiers, its per-channel cfg holds no destination secret — every
// smtp channel shares the one global relay; the channel's own config only
// picks recipients and a subject prefix.
type SMTP struct {
	Settings SMTPSettingsFunc
}

// Type returns TypeSMTP.
func (SMTP) Type() string { return TypeSMTP }

// Name is the type's GET /meta/schemas display name.
func (SMTP) Name() string { return "Email" }

// Schema returns the smtp channel's config JSON Schema ({to, subjectPrefix}).
func (SMTP) Schema() []byte { return smtpChannelSchema }

// Send emails ev to cfg's recipients through the live global "smtp"
// settings section, failing with "SMTP is not configured" when that
// section's host is empty (contract).
func (n SMTP) Send(ctx context.Context, ev Event, target Target, cfg map[string]any, _ map[string]string) error {
	server, password, err := n.Settings(ctx)
	if err != nil {
		return fmt.Errorf("notify: smtp: %w", err)
	}
	if server.Host == "" {
		return fmt.Errorf("notify: smtp: SMTP is not configured")
	}
	to := emailList(cfg["to"])
	if len(to) == 0 {
		return fmt.Errorf("notify: smtp: to is not configured")
	}
	prefix, _ := cfg["subjectPrefix"].(string)
	if prefix == "" {
		prefix = smtpDefaultSubjectPrefix
	}
	subject := prefix + " " + ev.Summary
	return SendMail(ctx, server, password, to, subject, smtpBody(ev, target))
}

// emailList converts a channel config's "to" JSON array — decoded by
// encoding/json as []any — to []string, skipping anything not a
// non-empty string.
func emailList(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// smtpBody renders ev as the plain-text lines Wire formats' SMTP row
// describes: summary, kind, severity, resource, time, allowlisted
// details, and — when CertForge's base URL is known and ev belongs to an
// org — a link to that org's events page.
func smtpBody(ev Event, target Target) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", ev.Summary)
	fmt.Fprintf(&b, "Kind: %s\n", ev.Kind)
	fmt.Fprintf(&b, "Severity: %s\n", ev.Severity)
	fmt.Fprintf(&b, "Resource: %s %s (%s)\n", ev.Resource.Type, ev.Resource.Name, ev.Resource.ID)
	fmt.Fprintf(&b, "Time: %s\n", ev.At.UTC().Format(time.RFC3339))
	details := filterDetails(ev.Kind, ev.Details)
	if len(details) > 0 {
		b.WriteString("Details:\n")
		keys := make([]string, 0, len(details))
		for k := range details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s: %v\n", k, details[k])
		}
	}
	// target carries the event's org name, not its slug (Target's doc
	// comment); the org id is used here in a slug's place until Target
	// gains one — cosmetic only, not a security-relevant value.
	if target.BaseURL != "" && ev.OrgID != nil {
		fmt.Fprintf(&b, "\n%s/o/%s/alerts/events\n", strings.TrimRight(target.BaseURL, "/"), ev.OrgID.String())
	}
	return b.String()
}
