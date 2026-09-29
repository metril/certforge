# 0017: Event model, exact-once emit, and per-channel delivery jobs

Status: accepted (Phase 6A)

## Context

Phase 6A needs a single, uniform way for the rest of CertForge (issuance,
deployment, agent/client health, external monitors, backup) to say "this
happened" and have it reach every configured notification channel — a
webhook, email, Discord, ntfy or Home Assistant — without each of those
future callers reimplementing matching, retrying and secret handling
itself, and without a burst of related conditions (three renewal failures
in five minutes, a flapping monitor) turning into a burst of duplicate
notifications.

Two shapes were considered for fanning an event out to channels: an
in-process pub/sub bus (callers publish, notifier goroutines subscribe) or
a durable table plus a job per (event, channel) pair. A bus is cheaper and
simpler, but loses everything queued if the process restarts mid-delivery,
and gives no natural place to retry one channel's failure independently of
the others, or to answer "what did we actually send, and did it land" —
`Channel.lastDelivery` and the events feed (`GET
/api/v1/orgs/{orgId}/events`) both need durable, queryable delivery state,
not a fire-and-forget notification.

## Decision

- **No event bus.** `notification_events` is a plain table (one row per
  condition) and `notification_deliveries` is one row per `(event,
  matched channel)` pair, populated by `Emit` in the same transaction as
  the event itself. Each delivery is its own `certforge_notify_deliver`
  river job (five attempts, the same one-shot-job shape as
  `deploy.DeployArgs`/`kek.RewrapArgs`), so a channel's failure retries
  and eventually gives up independently of every other channel's own
  delivery of the same event — and a process restart loses nothing:
  river's own queue is the durability.
- **Severity, resource type and dedupe key are fixed per kind, never
  chosen by the caller.** `SeverityOf`/`ResourceTypeOf` are lookup tables
  keyed by `Event.Kind`; a caller supplies the kind, the resource identity
  and a dedupe key built from the specific occurrence (a version id, a
  UTC day, a state-transition timestamp — see `docs/notifications.md
  #dedupe`), not the severity or resource type themselves. This keeps
  "what severity is a `monitor.mismatch`" a one-place answer instead of
  something every future emitter (issuance, deploy, monitor, backup) has
  to get right and keep in sync on its own.
- **Exact-once emit is a UNIQUE constraint, not application-level
  locking.** `notification_events.dedupe_key` is `UNIQUE`;
  `InsertNotificationEvent` is `INSERT ... ON CONFLICT (dedupe_key) DO
  NOTHING RETURNING id`, and zero rows back (surfaced by sqlc's `:one` as
  `pgx.ErrNoRows`) means the condition already fired — `Emit` treats that
  as `(false, nil)`, not an error. This is race-safe under concurrent
  emitters with no advisory lock: Postgres's own unique index is the
  single source of truth for "has this already happened."
- **Channel matching happens inside the same transaction as the event
  insert, locked `FOR KEY SHARE`.** `MatchingChannels` (enabled, org-owned
  or `all_orgs`, an empty or matching `events` filter, `minSeverity` at or
  below the event's own severity) locks each matched channel row, so a
  concurrent channel delete (which takes `FOR UPDATE`) serializes against
  it instead of racing a delivery job into existence for a channel that is
  disappearing. A global event (`orgId` nil) matches `all_orgs` channels
  only — `org_id = NULL` is never true in SQL, so the same `org_id = $org
  OR all_orgs` expression that matches an org-scoped event correctly
  excludes every org-scoped channel from a global one, with no
  special-casing.
- **`Emit`'s transaction is the caller's choice, not always its own.** A
  nil `tx` means `Emit` opens and commits its own transaction (the common
  case: a standalone condition like a monitor check completing). A
  non-nil `tx` — issuance raising `cert.issued` as part of the same
  transaction that just stored the certificate version, for instance —
  is used as-is; `Emit` neither commits nor rolls it back. A caller
  rollback then takes the event, its deliveries and their queued jobs
  with it: nothing is left half-recorded from an issuance that itself
  failed after generating the event.
- **`internal/notify/httpx` is one shared outbound client, not one per
  notifier.** Every HTTP-based notifier (webhook, Discord, ntfy, Home
  Assistant) and every external monitor's dial policy need the identical
  SSRF-safe dialer, redirect-refusal, retry budget and body cap; building
  that once here means a notifier implementation (Task 4) is just "shape
  the request and headers," not "also get the security policy right
  again." The policy runs twice on purpose — once at save time
  (`CheckURL`/`CheckHost`, so a bad address is rejected with a useful 422
  instead of failing silently at 2am) and again at actual dial time
  (`DialControl`, against the address DNS just resolved to) — because a
  hostname that was fine at save time can resolve to a blocked address
  later (DNS rebinding), and only the second check catches that.

## Consequences

- A future event source (issuance's `cert.issued`/`cert.renewal_failed`,
  the expiry/failure-threshold hourly scan, external monitor transitions,
  backup outcomes — Tasks 7 and 9) only ever calls `Emitter.Emit` with an
  `Event{Kind, OrgID, Resource, Summary, Details, DedupeKey}`; it never
  touches `notification_deliveries` or river directly, and never chooses
  a severity.
- `Notifier.Send`'s own errors are always redacted (`httpx.Redact`, every
  decrypted secret value plus its URL-escaped and path-escaped forms)
  before `DeliverWorker` stores them in `last_error` or lets river log
  them — Task 4/5's notifier implementations do not need their own
  redaction pass on top.
- `Payload` renders the wire body notifiers share (webhook and Home
  Assistant verbatim; Discord and ntfy build their own shape from the same
  `Event` in Task 4) through a fixed per-kind allowlist of `Details` keys,
  so a future event source that builds a slightly too-generous `Details`
  map can never leak an internal id or key material through it by
  accident — the allowlist, not the caller, decides what crosses the
  wire.
- A disabled channel or an unregistered notifier type never calls `Send`
  at all: `DeliverWorker` records a terminal failure (`"channel
  disabled"`) and returns `nil`, since no retry could ever fix either
  condition — river marks the job done rather than retrying it five times
  for nothing.
