package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/settings"
)

// Result is one inline delivery's outcome (Shared contract: DeliveryResult;
// testChannel and testSmtpSettings both return this shape).
type Result struct {
	Status   string // "delivered" or "failed"; an inline test never returns pending.
	Error    string // "" on success.
	Duration time.Duration
}

// EventDelivery is one channel's delivery outcome for an event (Shared
// contract: EventDelivery).
type EventDelivery struct {
	ChannelID   uuid.UUID
	ChannelName string
	Status      string
	Attempts    int
	LastError   string
	DeliveredAt *time.Time
}

// EventWithDeliveries is one feed entry: an Event plus its per-channel
// delivery outcomes (Shared contract: listEvents' Event schema, which adds
// deliveries to the base Event shape event.go defines for the emitter/
// notifier side).
type EventWithDeliveries struct {
	Event
	Deliveries []EventDelivery
}

// EventPage is one page of events (Shared contract: EventPage).
type EventPage struct {
	Items      []EventWithDeliveries
	NextCursor string // "" means no next page.
}

// EventFilter is listEvents' query parameters (Shared contract, Other
// operations row). Zero values mean "no filter"/"first page"/"default
// limit".
type EventFilter struct {
	Kinds       []string
	MinSeverity string
	Since       *time.Time
	Cursor      string
	Limit       int
}

// defaultEventPageLimit is ListEvents' page size when Limit is unset.
const defaultEventPageLimit = 50

// Service is channel CRUD, send-test and the events list (Shared contract,
// Channel and Other operations rows): schema validation, secret splitting,
// summaries and URL policy around Store's raw rows. It does not itself
// check authorization (including the allOrgs-needs-a-global-admin gate) —
// that is the API layer's job, the same as every other resource in this
// codebase.
type Service struct {
	Store    *Store
	Emitter  *Emitter
	Registry *Registry
	Box      crypto.Box
	Settings *settings.Store
	Audit    *audit.Auditor

	// BaseURL and Version fill Target for a testChannel Send, the same two
	// fields DeliverWorker carries for a real delivery (Target's own doc
	// comment: BaseURL only adds an optional link, Version only names the
	// webhook User-Agent — empty is a safe default for either).
	BaseURL, Version string

	Log *slog.Logger
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// RegisterRiver adds DeliverWorker to workers (task-3 brief: "Emitter/
// DeliverWorker have no RegisterRiver of their own in this task — that
// lands with Task 6's Service, which owns wiring DeliverWorker into
// river.Workers"). There is no periodic job here: a delivery is only ever
// enqueued reactively, by Emit (the hourly scan/prune job is Task 7's
// Sources/ScanArgs, registered separately).
func (s *Service) RegisterRiver(workers *river.Workers) []*river.PeriodicJob {
	river.AddWorker(workers, &DeliverWorker{Q: s.Store.Q, Box: s.Box, Registry: s.Registry,
		BaseURL: s.BaseURL, Version: s.Version, Log: s.log()})
	return nil
}

// audit records e, logging (never failing the caller) on error — the
// domain-level equivalent of internal/api's own Server.audit, since
// channel writes are audited by Service itself (Shared contract, Audit
// row: "channel.create/update/delete/test").
func (s *Service) audit(ctx context.Context, e audit.Event) {
	if s.Audit == nil {
		return
	}
	if err := s.Audit.Record(ctx, e); err != nil {
		s.log().Error("notify: audit record failed", "action", e.Action, "err", err)
	}
}

func channelAuditDetails(id uuid.UUID, typ string, allOrgs bool) map[string]any {
	return map[string]any{"channelId": id, "type": typ, "allOrgs": allOrgs}
}

// allowLoopback reads the live "notifications" section's allowLoopbackUrls
// (never cached — Current's own doc comment: an operator can flip it at
// any time).
func (s *Service) allowLoopback(ctx context.Context) (bool, error) {
	set, err := Current(ctx, s.Settings)
	if err != nil {
		return false, err
	}
	return set.AllowLoopbackURLs, nil
}

// lastDeliveries returns each id's most recent delivery, keyed by channel
// id; an id with no delivery yet is simply absent.
func (s *Service) lastDeliveries(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]ChannelLastDelivery, error) {
	out := map[uuid.UUID]ChannelLastDelivery{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.Store.Q.ChannelsLastDelivery(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ChannelID] = ChannelLastDelivery{Status: r.Status, At: r.UpdatedAt, Error: r.LastError}
	}
	return out, nil
}

func (s *Service) channelsFromRows(ctx context.Context, rows []sqlcgen.NotificationChannel) ([]Channel, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	last, err := s.lastDeliveries(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]Channel, 0, len(rows))
	for _, r := range rows {
		ch, err := channelFromRow(ctx, s.Box, r)
		if err != nil {
			return nil, err
		}
		if ld, ok := last[r.ID]; ok {
			ld := ld
			ch.LastDelivery = &ld
		}
		out = append(out, ch)
	}
	return out, nil
}

// ListChannels returns orgID's own channels, plus — only when
// includeAllOrgs is true (the caller's own global-admin check) — every
// other org's all_orgs channel.
func (s *Service) ListChannels(ctx context.Context, orgID uuid.UUID, includeAllOrgs bool) ([]Channel, error) {
	rows, err := s.Store.Q.ListOrgNotificationChannels(ctx, sqlcgen.ListOrgNotificationChannelsParams{
		OrgID: orgID, IncludeAllOrgs: includeAllOrgs})
	if err != nil {
		return nil, err
	}
	return s.channelsFromRows(ctx, rows)
}

// GetChannel returns one channel of orgID.
func (s *Service) GetChannel(ctx context.Context, orgID, id uuid.UUID) (Channel, error) {
	row, err := s.Store.Q.GetOrgNotificationChannel(ctx, sqlcgen.GetOrgNotificationChannelParams{ID: id, OrgID: orgID})
	if err != nil {
		return Channel{}, notFoundErr(err)
	}
	list, err := s.channelsFromRows(ctx, []sqlcgen.NotificationChannel{row})
	if err != nil {
		return Channel{}, err
	}
	return list[0], nil
}

// resolvedInput is a ChannelInput after schema validation, URL policy and
// (on update) secret merging, ready to split and store.
type resolvedInput struct {
	name        string
	events      []string
	minSeverity string
	cfg         map[string]any // full, resolved config: secret values included, no Unchanged sentinel
}

// validateInput runs the type-independent checks (name, events, severity),
// then the type's schema (ValidateConfig) and URL policy against cfg — the
// full resolved config a create or update is about to store.
func (s *Service) validateInput(ctx context.Context, in ChannelInput, cfg map[string]any) (resolvedInput, error) {
	name, err := checkChannelName(in.Name)
	if err != nil {
		return resolvedInput{}, err
	}
	if err := checkEvents(in.Events); err != nil {
		return resolvedInput{}, err
	}
	minSeverity := in.MinSeverity
	if minSeverity == "" {
		minSeverity = "info"
	}
	if err := checkSeverity(minSeverity); err != nil {
		return resolvedInput{}, err
	}
	if _, ok := s.Registry.Get(in.Type); !ok {
		return resolvedInput{}, &ValidationError{Field: "type", Msg: fmt.Sprintf("unknown channel type %q", in.Type)}
	}
	if err := s.Registry.ValidateConfig(in.Type, cfg); err != nil {
		return resolvedInput{}, &ValidationError{Field: "config", Msg: err.Error()}
	}
	allowLoopback, err := s.allowLoopback(ctx)
	if err != nil {
		return resolvedInput{}, err
	}
	if err := checkChannelURL(in.Type, cfg, allowLoopback); err != nil {
		return resolvedInput{}, err
	}
	events := in.Events
	if events == nil {
		events = []string{}
	}
	return resolvedInput{name: name, events: events, minSeverity: minSeverity, cfg: cfg}, nil
}

// CreateChannel validates in and stores a new channel.
func (s *Service) CreateChannel(ctx context.Context, orgID uuid.UUID, in ChannelInput) (Channel, error) {
	resolved, err := s.validateInput(ctx, in, in.Config)
	if err != nil {
		return Channel{}, err
	}
	secretKeys, _ := s.Registry.SecretKeys(in.Type)
	public, secret, err := splitChannelConfig(secretKeys, resolved.cfg)
	if err != nil {
		return Channel{}, err
	}
	count, err := s.Store.Q.CountNotificationChannels(ctx, orgID)
	if err != nil {
		return Channel{}, err
	}
	if count >= maxChannelsPerOrg {
		return Channel{}, &ValidationError{Field: "name", Msg: "at most 50 channels per org"}
	}
	publicJSON, err := json.Marshal(public)
	if err != nil {
		return Channel{}, err
	}
	sealed, err := sealSecrets(ctx, s.Box, secret)
	if err != nil {
		return Channel{}, err
	}
	row, err := s.Store.Q.CreateNotificationChannel(ctx, sqlcgen.CreateNotificationChannelParams{
		OrgID: orgID, Name: resolved.name, Type: in.Type, Config: publicJSON, SecretCfg: sealed,
		Events: resolved.events, MinSeverity: resolved.minSeverity, AllOrgs: in.AllOrgs, Enabled: in.Enabled})
	if pgCode(err) == pgUniqueViolation {
		return Channel{}, &ConflictError{Msg: fmt.Sprintf("a channel named %q exists in this org", resolved.name)}
	}
	if err != nil {
		return Channel{}, err
	}
	out, err := channelFromRow(ctx, s.Box, row)
	if err != nil {
		return Channel{}, err
	}
	s.audit(ctx, audit.Event{Action: "channel.create", ResourceType: "channel", ResourceID: row.ID.String(), OrgID: &orgID,
		Details: channelAuditDetails(row.ID, row.Type, row.AllOrgs)})
	return out, nil
}

// UpdateChannel replaces name/config/events/minSeverity/allOrgs/enabled;
// type is immutable (the caller's job to reject a type change as 422
// before calling this, so the exact wording matches the Shared contract's
// "type cannot change"). A secret config field sent as Unchanged or
// omitted keeps its stored value; changing the type's reentry field
// (checkChannelReentry) or, for webhook, changing url to a fresh,
// different value while authHeader/signingSecret are kept
// (checkWebhookReentry) is a 422.
func (s *Service) UpdateChannel(ctx context.Context, orgID, id uuid.UUID, in ChannelInput) (Channel, error) {
	cur, err := s.Store.Q.GetOrgNotificationChannel(ctx, sqlcgen.GetOrgNotificationChannelParams{ID: id, OrgID: orgID})
	if err != nil {
		return Channel{}, notFoundErr(err)
	}
	var oldPublic map[string]any
	if len(cur.Config) > 0 {
		if err := json.Unmarshal(cur.Config, &oldPublic); err != nil {
			return Channel{}, err
		}
	}
	oldSecret, err := resolveChannelSecrets(ctx, s.Box, cur.SecretCfg)
	if err != nil {
		return Channel{}, err
	}
	secretKeys, _ := s.Registry.SecretKeys(cur.Type)
	resolvedCfg, reused := mergeChannelConfig(secretKeys, oldSecret, in.Config)

	resolved, err := s.validateInput(ctx, in, resolvedCfg)
	if err != nil {
		return Channel{}, err
	}
	if err := checkChannelReentry(cur.Type, oldPublic, resolved.cfg, reused); err != nil {
		return Channel{}, err
	}
	if err := checkWebhookReentry(cur.Type, oldSecret, resolved.cfg, reused); err != nil {
		return Channel{}, err
	}
	public, secret, err := splitChannelConfig(secretKeys, resolved.cfg)
	if err != nil {
		return Channel{}, err
	}
	publicJSON, err := json.Marshal(public)
	if err != nil {
		return Channel{}, err
	}
	sealed, err := sealSecrets(ctx, s.Box, secret)
	if err != nil {
		return Channel{}, err
	}
	row, err := s.Store.Q.UpdateNotificationChannel(ctx, sqlcgen.UpdateNotificationChannelParams{
		ID: id, OrgID: orgID, Name: resolved.name, Config: publicJSON, SecretCfg: sealed,
		Events: resolved.events, MinSeverity: resolved.minSeverity, AllOrgs: in.AllOrgs, Enabled: in.Enabled})
	if pgCode(err) == pgUniqueViolation {
		return Channel{}, &ConflictError{Msg: fmt.Sprintf("a channel named %q exists in this org", resolved.name)}
	}
	if err != nil {
		return Channel{}, err
	}
	out, err := s.GetChannel(ctx, orgID, id)
	if err != nil {
		return Channel{}, err
	}
	s.audit(ctx, audit.Event{Action: "channel.update", ResourceType: "channel", ResourceID: row.ID.String(), OrgID: &orgID,
		Details: channelAuditDetails(row.ID, row.Type, row.AllOrgs)})
	return out, nil
}

// DeleteChannel removes a channel, locked FOR UPDATE for the delete
// (global-constraints Locking row), inside one transaction.
func (s *Service) DeleteChannel(ctx context.Context, orgID, id uuid.UUID) error {
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Store.Q.WithTx(tx)
	cur, err := q.LockOrgNotificationChannel(ctx, sqlcgen.LockOrgNotificationChannelParams{ID: id, OrgID: orgID})
	if err != nil {
		return notFoundErr(err)
	}
	n, err := q.DeleteNotificationChannel(ctx, sqlcgen.DeleteNotificationChannelParams{ID: id, OrgID: orgID})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrChannelNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.audit(ctx, audit.Event{Action: "channel.delete", ResourceType: "channel", ResourceID: id.String(), OrgID: &orgID,
		Details: channelAuditDetails(id, cur.Type, cur.AllOrgs)})
	return nil
}

// testSummary is the fixed summary a test event carries (Shared contract's
// dedupe key row names the kind "test"; the wording itself is not
// contract-bound).
func testSummary(channelName string) string {
	return fmt.Sprintf("Test notification from CertForge to %q", channelName)
}

// Test sends a one-off "test" event to exactly this channel — never
// through Emitter/MatchingChannels, which would fan it out to every
// channel the event happens to match — inline, bound to testTimeout, and
// regardless of the channel's own Enabled (Shared contract: "allowed when
// disabled"). The result is always returned as a Result, never as an
// error: a delivery failure is an ordinary (200) outcome, not an API
// error.
func (s *Service) Test(ctx context.Context, orgID, id uuid.UUID) (Result, error) {
	row, err := s.Store.Q.GetOrgNotificationChannel(ctx, sqlcgen.GetOrgNotificationChannelParams{ID: id, OrgID: orgID})
	if err != nil {
		return Result{}, notFoundErr(err)
	}
	notifier, ok := s.Registry.Get(row.Type)
	if !ok {
		return Result{}, fmt.Errorf("notify: unknown channel type %q", row.Type)
	}
	var cfg map[string]any
	if len(row.Config) > 0 {
		if err := json.Unmarshal(row.Config, &cfg); err != nil {
			return Result{}, err
		}
	}
	secrets, err := resolveChannelSecrets(ctx, s.Box, row.SecretCfg)
	if err != nil {
		return Result{}, err
	}

	dedupeKey := "test:" + uuid.NewString()
	eventID, err := s.Store.Q.InsertNotificationEvent(ctx, sqlcgen.InsertNotificationEventParams{
		OrgID: &orgID, Kind: "test", Severity: SeverityOf("test"), ResourceType: ResourceTypeOf("test"),
		ResourceID: row.ID.String(), ResourceName: row.Name, Summary: testSummary(row.Name),
		Details: []byte(`{}`), DedupeKey: dedupeKey})
	if err != nil {
		return Result{}, err
	}
	eventRow, err := s.Store.Q.GetNotificationEvent(ctx, eventID)
	if err != nil {
		return Result{}, err
	}
	if err := s.Store.Q.InsertNotificationDelivery(ctx, sqlcgen.InsertNotificationDeliveryParams{
		EventID: eventID, ChannelID: id}); err != nil {
		return Result{}, err
	}

	target, err := s.testTarget(ctx, orgID)
	if err != nil {
		return Result{}, err
	}
	sendCtx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()
	start := time.Now()
	sendErr := notifier.Send(sendCtx, toEvent(eventRow), target, cfg, secrets)
	duration := time.Since(start)

	res := Result{Duration: duration}
	if sendErr != nil {
		msg := truncateUTF8(httpx.Redact(sendErr.Error(), secretValues(secrets)...), maxLastError)
		res.Status, res.Error = "failed", msg
		if err := s.Store.Q.MarkNotificationDeliveryFailed(ctx, sqlcgen.MarkNotificationDeliveryFailedParams{
			EventID: eventID, ChannelID: id, Attempts: 1, Status: "failed", LastError: msg}); err != nil {
			s.log().Error("notify: test delivery failure not recorded", "channel", id, "err", err)
		}
	} else {
		res.Status = "delivered"
		if err := s.Store.Q.MarkNotificationDeliveryDelivered(ctx, sqlcgen.MarkNotificationDeliveryDeliveredParams{
			EventID: eventID, ChannelID: id, Attempts: 1}); err != nil {
			s.log().Error("notify: test delivery success not recorded", "channel", id, "err", err)
		}
	}
	s.audit(ctx, audit.Event{Action: "channel.test", ResourceType: "channel", ResourceID: id.String(), OrgID: &orgID,
		Details: channelAuditDetails(id, row.Type, row.AllOrgs)})
	return res, nil
}

// testTarget builds Test's Target: OrgName is the owning org's current
// display name (a channel always belongs to one org, even when AllOrgs
// also delivers its events elsewhere).
func (s *Service) testTarget(ctx context.Context, orgID uuid.UUID) (Target, error) {
	org, err := s.Store.Q.GetOrg(ctx, orgID)
	if err != nil {
		return Target{}, err
	}
	return Target{OrgName: org.Name, BaseURL: s.BaseURL, Version: s.Version}, nil
}

// ---- events ----

// eventCursor is ListEvents' opaque nextCursor/cursor payload: base64url
// JSON of the last row's (at, id) keyset position (same shape as the
// notification_events_org_at index ORDER BY at DESC, id DESC).
type eventCursor struct {
	At time.Time `json:"at"`
	ID uuid.UUID `json:"id"`
}

func encodeEventCursor(c eventCursor) string {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err) // eventCursor always marshals
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeEventCursor decodes s, or reports it as a ValidationError when it
// is not a cursor this package issued (opaque to the caller, unbound to
// any particular filter — a forged or stale one only ever names a
// position in the single (at, id) ordering, which carries no scope of its
// own to smuggle past the org-scoped query itself).
func decodeEventCursor(s string) (eventCursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return eventCursor{}, &ValidationError{Field: "cursor", Msg: "cursor is not from this list"}
	}
	var c eventCursor
	if err := json.Unmarshal(b, &c); err != nil {
		return eventCursor{}, &ValidationError{Field: "cursor", Msg: "cursor is not from this list"}
	}
	return c, nil
}

// ListEvents returns one page of orgID's events (its own, plus every
// global event), newest first.
func (s *Service) ListEvents(ctx context.Context, orgID uuid.UUID, f EventFilter) (EventPage, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultEventPageLimit
	}
	params := sqlcgen.ListOrgEventsParams{OrgID: &orgID, PageLimit: int32(limit + 1)}
	if len(f.Kinds) > 0 {
		params.HasKinds, params.Kinds = true, f.Kinds
	}
	if f.MinSeverity != "" {
		params.HasSeverity, params.MinSeverity = true, f.MinSeverity
	}
	if f.Since != nil {
		params.HasSince, params.Since = true, *f.Since
	}
	if f.Cursor != "" {
		c, err := decodeEventCursor(f.Cursor)
		if err != nil {
			return EventPage{}, err
		}
		params.HasCursor, params.BeforeAt, params.BeforeID = true, c.At, c.ID
	}
	rows, err := s.Store.Q.ListOrgEvents(ctx, params)
	if err != nil {
		return EventPage{}, err
	}
	var next string
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[limit-1]
		next = encodeEventCursor(eventCursor{At: last.At, ID: last.ID})
	}
	deliveries, err := s.eventDeliveries(ctx, rows)
	if err != nil {
		return EventPage{}, err
	}
	items := make([]EventWithDeliveries, 0, len(rows))
	for _, r := range rows {
		items = append(items, EventWithDeliveries{Event: toEvent(r), Deliveries: deliveries[r.ID]})
	}
	return EventPage{Items: items, NextCursor: next}, nil
}

// eventDeliveries fetches every delivery for rows' events in one round
// trip, keyed by event id; an event with no matching channel has no
// entry (nil, which callers treat as an empty slice).
func (s *Service) eventDeliveries(ctx context.Context, rows []sqlcgen.NotificationEvent) (map[uuid.UUID][]EventDelivery, error) {
	out := map[uuid.UUID][]EventDelivery{}
	if len(rows) == 0 {
		return out, nil
	}
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	drows, err := s.Store.Q.EventDeliveries(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, d := range drows {
		out[d.EventID] = append(out[d.EventID], EventDelivery{
			ChannelID: d.ChannelID, ChannelName: d.ChannelName, Status: d.Status,
			Attempts: int(d.Attempts), LastError: d.LastError, DeliveredAt: d.DeliveredAt})
	}
	return out, nil
}

// sealSecrets marshals and seals secrets, or returns nil for an empty map
// (notification_channels.secret_cfg is nullable — a channel with no
// secret fields set stores none, the same convention deliver.go's own
// len(channel.SecretCfg) > 0 check relies on).
func sealSecrets(ctx context.Context, box crypto.Box, secrets map[string]string) ([]byte, error) {
	if len(secrets) == 0 {
		return nil, nil
	}
	pt, err := json.Marshal(secrets)
	if err != nil {
		return nil, err
	}
	return box.Seal(ctx, pt)
}
