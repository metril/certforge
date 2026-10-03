package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/notify/httpx"
)

// Unchanged is a channel secret field's write-only sentinel (Shared
// contract: updateChannel "secrets __unchanged__ or omitted keep the
// stored ones"; the same value and role as settings.Unchanged and
// challenge.Unchanged, kept as its own constant here since this package
// has no dependency on either).
const Unchanged = "__unchanged__"

// maxChannelsPerOrg is CreateChannel's per-org limit (Shared contract:
// "At most 50 channels per org (422)").
const maxChannelsPerOrg = 50

// maxSummaryLen bounds Channel.Summary (Shared contract: "summary string
// (<= 200)").
const maxSummaryLen = 200

// testTimeout bounds testChannel's inline Send (Shared contract:
// "10 s bound").
const testTimeout = 10 * time.Second

// ErrChannelNotFound means a channel id does not exist in the org.
var ErrChannelNotFound = errors.New("notify: channel not found")

// ValidationError is a 422: a bad name, type, config, events entry or
// severity, the per-org channel limit, or the config re-entry rule.
type ValidationError struct{ Field, Msg string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

// ConflictError is a 409: a channel name already used in the org.
type ConflictError struct{ Msg string }

func (e *ConflictError) Error() string { return e.Msg }

// ChannelLastDelivery is a channel's most recent delivery attempt, across
// every event (Shared contract: Channel.lastDelivery).
type ChannelLastDelivery struct {
	Status string
	At     time.Time
	Error  string
}

// Channel is a stored notification channel (Shared contract: Channel
// schema), with its secrets already split out: Config holds only the
// type's public fields, StoredSecrets names the secret fields that hold a
// value, and Summary is a non-secret display line derived from the full
// (public + decrypted secret) config.
type Channel struct {
	ID, OrgID            uuid.UUID
	Name                 string
	Type                 string
	Config               map[string]any
	StoredSecrets        []string
	Summary              string
	Events               []string
	MinSeverity          string
	AllOrgs              bool
	Enabled              bool
	LastDelivery         *ChannelLastDelivery
	CreatedAt, UpdatedAt time.Time
}

// ChannelInput is a create or update's resolved fields (defaults already
// applied by the caller — Shared contract: ChannelInput's own defaults).
// Config carries the full submitted config, secret field values included
// (and, on update, a secret field may be Unchanged or simply omitted to
// keep the stored value).
type ChannelInput struct {
	Name        string
	Type        string
	Config      map[string]any
	Events      []string
	MinSeverity string
	AllOrgs     bool
	Enabled     bool
}

// Store wraps direct Postgres access for notification channels and events
// (notification_channels/events/deliveries), the way issuance.Store and
// certstore.Store wrap their own tables. Service does the schema-aware
// work (validation, secret splitting, summaries); Store only reads and
// writes rows.
type Store struct {
	Pool *pgxpool.Pool
	Q    *sqlcgen.Queries
}

// reentryField is the Deviations R3 rule: a type whose secret composes a
// destination with a separate, readable URL-ish field. Changing that field
// while the type's secret is kept Unchanged is refused (422 "re-enter the
// secret") — an old secret would otherwise silently carry over to what may
// be a different destination. discord has no such field (its whole URL is
// itself the secret, and it carries no other secret alongside it); smtp
// has none of its own (channel-level "to"/"subjectPrefix" carry no secret
// at all). webhook's url is itself the secret too, but — unlike discord —
// it has two more secrets of its own (authHeader, signingSecret) that
// travel with it to whatever host url names; that needs its own rule,
// checkWebhookReentry, since this map's single-field shape (a secret kept
// vs. one separate public field changing) cannot express it.
var reentryField = map[string]string{
	TypeNtfy:          "server",
	TypeHomeAssistant: "baseUrl",
}

// channelURLField is the config field httpx.CheckURL runs against at
// create/update time (Shared contract, pre-flight ruling: "URL policy
// re-checked at create/update (422) and at send"), keyed by channel type.
// Only the field that determines the destination host is checked — ntfy's
// topic and homeassistant's webhookId are path segments, not hosts, so
// they need no host-level SSRF check of their own. smtp and a type with no
// entry here need no create/update-time URL check.
func channelURLField(typ string) (field string, ok bool) {
	switch typ {
	case TypeWebhook:
		return "url", true
	case TypeDiscord:
		return "webhookUrl", true
	case TypeNtfy:
		return "server", true
	case TypeHomeAssistant:
		return "baseUrl", true
	default:
		return "", false
	}
}

// Summary computes a channel's non-secret display line (Shared contract:
// Channel.summary; pre-flight ruling: "computed by notify.Summary from
// url.Hostname() only"). cfg is the channel's public config; secrets is
// its decrypted secret_cfg — needed here only to read a URL-shaped
// secret's hostname, never returned or logged whole.
func Summary(typ string, cfg map[string]any, secrets map[string]string) string {
	var s string
	switch typ {
	case TypeWebhook:
		s = hostnameOf(secrets["url"])
	case TypeDiscord:
		s = "Discord webhook"
	case TypeNtfy:
		server, _ := cfg["server"].(string)
		if server == "" {
			server = ntfyDefaultServer
		}
		topic, _ := cfg["topic"].(string)
		s = hostnameOf(server) + "/" + topic
	case TypeHomeAssistant:
		baseURL, _ := cfg["baseUrl"].(string)
		s = hostnameOf(baseURL)
	case TypeSMTP:
		s = strings.Join(emailList(cfg["to"]), ", ")
	}
	return truncate(s, maxSummaryLen)
}

// hostnameOf returns raw's URL hostname (no scheme, port, path, query or
// userinfo), or "" for an unparseable or empty URL.
func hostnameOf(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// splitChannelConfig separates cfg's secret fields (schema-declared
// "secret": true, per secretKeys) from the rest, for storage: public goes
// to notification_channels.config, secret (only non-empty values) is
// sealed into secret_cfg. cfg must already have passed
// Registry.ValidateConfig (the caller's job), so every secret key's value
// here is either absent or a string.
func splitChannelConfig(secretKeys []string, cfg map[string]any) (public map[string]any, secret map[string]string, err error) {
	isSecret := make(map[string]bool, len(secretKeys))
	for _, k := range secretKeys {
		isSecret[k] = true
	}
	public = map[string]any{}
	secret = map[string]string{}
	for k, v := range cfg {
		if !isSecret[k] {
			public[k] = v
			continue
		}
		s, ok := v.(string)
		if !ok {
			return nil, nil, fmt.Errorf("notify: %s must be a string", k)
		}
		if s == "" {
			continue
		}
		if s == Unchanged {
			return nil, nil, &ValidationError{Field: "config." + k, Msg: "no stored secret to keep on create; provide one"}
		}
		secret[k] = s
	}
	return public, secret, nil
}

// mergeChannelConfig applies an update: every submitted key (secret or
// not) replaces the stored one, except a secret field left Unchanged or
// left out of in entirely, which both keep the stored value (Shared
// contract: "secrets __unchanged__ or omitted keep the stored ones" —
// unlike a non-secret field, which is always a full replacement, and
// unlike DNS credential config, whose own MergeUpdate treats an omitted
// secret as cleared, not kept). A secret field explicitly sent as ""
// clears it. reused lists exactly the secret keys that were actually
// carried over from a stored value — never merely "left as Unchanged/
// omitted with nothing stored to keep" (batch-2 review finding 2: an ntfy
// channel with no token ever set must not need its token "re-entered"
// just because its server changed — checkChannelReentry's whole premise is
// that a real, already-stored secret would otherwise silently apply to a
// new destination, which cannot happen when there is no stored secret at
// all), for checkChannelReentry and checkWebhookReentry.
func mergeChannelConfig(secretKeys []string, oldSecret map[string]string, in map[string]any) (resolved map[string]any, reused map[string]bool) {
	resolved = make(map[string]any, len(in)+len(secretKeys))
	for k, v := range in {
		resolved[k] = v
	}
	reused = map[string]bool{}
	for _, k := range secretKeys {
		v, present := resolved[k]
		kept := !present
		if present {
			if s, ok := v.(string); ok && s == Unchanged {
				kept = true
			}
		}
		if kept {
			if old, ok := oldSecret[k]; ok {
				reused[k] = true
				resolved[k] = old
			} else {
				delete(resolved, k)
			}
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			delete(resolved, k) // explicit clear
		}
	}
	return resolved, reused
}

// checkChannelReentry enforces the Deviations R3 rule (reentryField's doc
// comment): typ's reentry field changing while any secret was reused
// (kept from a stored value) is a 422. oldPublic/newPublic are the type's
// public config before and after the update. Every type reentryField
// covers has exactly one secret property (Registry.SecretKeys), so
// "any secret reused" and "that one secret reused" are the same thing;
// checkWebhookReentry is the counterpart for webhook, whose three secrets
// need a finer-grained rule reused alone cannot express.
func checkChannelReentry(typ string, oldPublic, newPublic map[string]any, reused map[string]bool) error {
	field, ok := reentryField[typ]
	if !ok || len(reused) == 0 {
		return nil
	}
	ob, _ := json.Marshal(oldPublic[field])
	nb, _ := json.Marshal(newPublic[field])
	if !bytes.Equal(ob, nb) {
		return &ValidationError{Field: "config." + field, Msg: "re-enter the secret"}
	}
	return nil
}

// checkWebhookReentry is checkChannelReentry's webhook-specific
// counterpart (batch-2 review finding 3; Vault/R3 rationale, plan gap):
// webhook's url is itself both the destination and its own secret, so
// changing it to a fresh, genuinely different value while authHeader or
// signingSecret are carried over unchanged would silently send that
// stored credential to whatever new host the caller named — any
// alerts:write holder could repoint a channel's url and have CertForge
// hand it the previously configured Authorization header or signing key
// on the next event. A no-op for every type but webhook (reentryField's
// single-field shape cannot express "one secret field gates two others",
// so this rule lives on its own rather than folded into reentryField).
func checkWebhookReentry(typ string, oldSecret map[string]string, resolved map[string]any, reused map[string]bool) error {
	if typ != TypeWebhook {
		return nil
	}
	newURL, _ := resolved["url"].(string)
	if newURL == "" || newURL == oldSecret["url"] {
		return nil // kept, cleared (the schema's own "required" rejects that), or a fresh value identical to what's stored
	}
	if reused["authHeader"] || reused["signingSecret"] {
		return &ValidationError{Field: "config.url", Msg: "re-enter the secret"}
	}
	return nil
}

// checkEvents validates a ChannelInput.Events list: every entry must be a
// known EventKind (Shared contract: "Every events item must be a known
// kind").
func checkEvents(events []string) error {
	for _, k := range events {
		if !IsKind(k) {
			return &ValidationError{Field: "events", Msg: fmt.Sprintf("unknown event kind %q", k)}
		}
	}
	return nil
}

// checkSeverity validates a ChannelInput.MinSeverity value.
func checkSeverity(sev string) error {
	if SeverityRank(sev) < 0 {
		return &ValidationError{Field: "minSeverity", Msg: fmt.Sprintf("unknown severity %q", sev)}
	}
	return nil
}

// checkChannelName validates a ChannelInput.Name value (Shared contract:
// Channel.name, 1-100).
func checkChannelName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" || len(n) > 100 {
		return "", &ValidationError{Field: "name", Msg: "must be 1 to 100 characters"}
	}
	return n, nil
}

// checkChannelURL runs httpx.CheckURL against typ's destination-host field
// (channelURLField) — the pre-flight ruling's create/update-time URL
// policy check, independent of the notifier's own re-check at Send. cfg is
// the fully resolved submitted config (secret fields included, any
// Unchanged sentinel already merged away by the caller), never a
// post-split public-only map: a secret URL field (webhook's url,
// discord's webhookUrl) only has its real value there.
func checkChannelURL(typ string, cfg map[string]any, allowLoopback bool) error {
	field, ok := channelURLField(typ)
	if !ok {
		return nil
	}
	raw, _ := cfg[field].(string)
	if raw == "" && field == "server" && typ == TypeNtfy {
		raw = ntfyDefaultServer
	}
	if raw == "" {
		// The schema's own "required" (webhook/discord/homeassistant) or
		// default (ntfy) already guarantees a value by the time
		// ValidateConfig has passed; an empty value here is not this
		// check's job to reject.
		return nil
	}
	if err := httpx.CheckURL(raw, allowLoopback); err != nil {
		return &ValidationError{Field: "config." + field, Msg: err.Error()}
	}
	return nil
}

// resolveChannelSecrets opens ch's sealed secret_cfg (empty map for a
// channel with none stored).
func resolveChannelSecrets(ctx context.Context, box crypto.Box, sealed []byte) (map[string]string, error) {
	if len(sealed) == 0 {
		return map[string]string{}, nil
	}
	pt, err := box.Open(ctx, sealed)
	if err != nil {
		return nil, fmt.Errorf("notify: open channel secrets: %w", err)
	}
	var secrets map[string]string
	if err := json.Unmarshal(pt, &secrets); err != nil {
		return nil, fmt.Errorf("notify: decode channel secrets: %w", err)
	}
	if secrets == nil {
		secrets = map[string]string{}
	}
	return secrets, nil
}

// storedSecretKeys returns secrets' keys, sorted, never nil (Shared
// contract: Channel.storedSecrets serializes as [] rather than null).
func storedSecretKeys(secrets map[string]string) []string {
	out := make([]string, 0, len(secrets))
	for k := range secrets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// channelFromRow builds a Channel (with a computed Summary) from a stored
// row, opening its secrets to do so; the secrets themselves are discarded
// once Summary and StoredSecrets are computed — never carried into the
// returned Channel or an API response (TestChannelReadNeverReturnsSecrets).
func channelFromRow(ctx context.Context, box crypto.Box, row sqlcgen.NotificationChannel) (Channel, error) {
	var cfg map[string]any
	if len(row.Config) > 0 {
		if err := json.Unmarshal(row.Config, &cfg); err != nil {
			return Channel{}, err
		}
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	// The stored names come from the plaintext column; the sealed value is
	// opened only when Summary reads a secret (webhook's URL host) or for a
	// row written before the column existed (sealed value, no names).
	names := row.StoredSecretKeys
	var secrets map[string]string
	if len(row.SecretCfg) > 0 && (row.Type == TypeWebhook || len(names) == 0) {
		var err error
		if secrets, err = resolveChannelSecrets(ctx, box, row.SecretCfg); err != nil {
			return Channel{}, err
		}
		if len(names) == 0 {
			names = storedSecretKeys(secrets)
		}
	}
	if names == nil {
		names = []string{}
	}
	events := row.Events
	if events == nil {
		events = []string{}
	}
	return Channel{
		ID: row.ID, OrgID: row.OrgID, Name: row.Name, Type: row.Type, Config: cfg,
		StoredSecrets: names, Summary: Summary(row.Type, cfg, secrets),
		Events: events, MinSeverity: row.MinSeverity, AllOrgs: row.AllOrgs, Enabled: row.Enabled,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}, nil
}

// notFoundErr maps pgx.ErrNoRows to ErrChannelNotFound.
func notFoundErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrChannelNotFound
	}
	return err
}

// pgUniqueViolation is the Postgres SQLSTATE for a unique-constraint
// violation (notification_channels' UNIQUE(org_id, name)).
const pgUniqueViolation = "23505"

// pgCode returns err's Postgres SQLSTATE code, or "" when err isn't one
// (same helper as internal/api's own pgCode, duplicated here rather than
// imported: internal/api imports internal/notify, so the reverse import
// would cycle).
func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}
