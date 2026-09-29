-- name: InsertNotificationEvent :one
-- Emit's exact-once guard (Shared contract's Dedupe keys row): a UNIQUE
-- violation on dedupe_key is swallowed here via ON CONFLICT DO NOTHING, so
-- Emit sees zero rows back and treats the event as an already-fired
-- duplicate instead of erroring.
INSERT INTO notification_events (org_id, kind, severity, resource_type, resource_id, resource_name, summary, details, dedupe_key)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (dedupe_key) DO NOTHING
RETURNING id;

-- name: MatchingChannels :many
-- Emit's channel match (task-3 brief): enabled, org-owned or all_orgs, an
-- empty events list or an explicit kind match, and a minSeverity at or
-- below the event's own severity. A global event (org_id NULL) matches
-- all_orgs channels only: "org_id = NULL" is never true in SQL, so the OR
-- falls through to all_orgs alone with no special-casing needed. FOR KEY
-- SHARE locks each matched channel row so a concurrent channel delete
-- (which takes FOR UPDATE) serializes against this emit instead of racing
-- it (global-constraints Locking row).
SELECT id FROM notification_channels
WHERE enabled
  AND (org_id = sqlc.narg(org_id) OR all_orgs)
  AND (cardinality(events) = 0 OR sqlc.arg(kind)::text = ANY(events))
  AND (CASE min_severity WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END)
      <= (CASE sqlc.arg(severity)::text WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END)
FOR KEY SHARE;

-- name: InsertNotificationDelivery :exec
INSERT INTO notification_deliveries (event_id, channel_id) VALUES ($1, $2)
ON CONFLICT (event_id, channel_id) DO NOTHING;

-- name: GetNotificationDelivery :one
SELECT * FROM notification_deliveries WHERE event_id = $1 AND channel_id = $2;

-- name: GetNotificationEvent :one
SELECT * FROM notification_events WHERE id = $1;

-- name: GetNotificationChannel :one
SELECT * FROM notification_channels WHERE id = $1;

-- name: MarkNotificationDeliveryFailed :exec
-- status is 'failed' once the worker's own attempt count has reached the
-- job's MaxAttempts, else 'pending' (still retryable) — DeliverWorker
-- decides which and passes it in, since only it knows river's MaxAttempts.
UPDATE notification_deliveries SET attempts = $3, status = $4, last_error = $5, updated_at = now()
WHERE event_id = $1 AND channel_id = $2;

-- name: MarkNotificationDeliveryDelivered :exec
UPDATE notification_deliveries SET attempts = $3, status = 'delivered', last_error = '', delivered_at = now(), updated_at = now()
WHERE event_id = $1 AND channel_id = $2;

-- ---- Task 6: channel CRUD, lastDelivery and the events list ----

-- name: CountNotificationChannels :one
-- CreateChannel's per-org limit check (Shared contract: "at most 50
-- channels per org").
SELECT count(*) FROM notification_channels WHERE org_id = $1;

-- name: ListOrgNotificationChannels :many
-- listChannels (Shared contract, Channel operations row): the org's own
-- channels, plus — only when include_all_orgs is set by the caller (a
-- global admin) — every other org's all_orgs channel. A non-admin caller
-- passes include_all_orgs=false and sees only its own org's rows, whether
-- or not they are themselves all_orgs.
SELECT * FROM notification_channels
WHERE org_id = sqlc.arg(org_id)
   OR (sqlc.arg(include_all_orgs)::bool AND all_orgs AND org_id != sqlc.arg(org_id))
ORDER BY lower(name), id;

-- name: GetOrgNotificationChannel :one
SELECT * FROM notification_channels WHERE id = $1 AND org_id = $2;

-- name: LockOrgNotificationChannel :one
-- DeleteChannel's own lock (global-constraints Locking row: "channel
-- delete locks FOR UPDATE"), taken before the delete in the same
-- transaction so a concurrent Emit's FOR KEY SHARE (MatchingChannels)
-- serializes against it instead of racing it.
SELECT * FROM notification_channels WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- name: CreateNotificationChannel :one
INSERT INTO notification_channels (org_id, name, type, config, secret_cfg, events, min_severity, all_orgs, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: UpdateNotificationChannel :one
UPDATE notification_channels SET name = sqlc.arg(name), config = sqlc.arg(config), secret_cfg = sqlc.arg(secret_cfg),
       events = sqlc.arg(events), min_severity = sqlc.arg(min_severity), all_orgs = sqlc.arg(all_orgs),
       enabled = sqlc.arg(enabled), updated_at = now()
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) RETURNING *;

-- name: DeleteNotificationChannel :execrows
DELETE FROM notification_channels WHERE id = $1 AND org_id = $2;

-- name: ChannelsLastDelivery :many
-- One row per channel (its most recently updated delivery), backing
-- Channel.lastDelivery. A channel with no delivery yet is simply absent
-- from the result (the caller treats a missing id as null).
SELECT DISTINCT ON (channel_id) channel_id, status, last_error, delivered_at, updated_at
FROM notification_deliveries
WHERE channel_id = ANY(sqlc.arg(channel_ids)::uuid[])
ORDER BY channel_id, updated_at DESC;

-- name: ListOrgEvents :many
-- listEvents (Shared contract, Other operations row): the org's own events
-- plus every global (org_id NULL) event, newest first, keyset-paginated on
-- (at, id) since two events can share the same at timestamp. severity is a
-- minimum (the same rank comparison MatchingChannels uses); kind, when
-- given, is a set (the caller repeats ?kind=).
SELECT * FROM notification_events
WHERE (org_id = sqlc.arg(org_id) OR org_id IS NULL)
  AND (NOT sqlc.arg(has_kinds)::bool OR kind = ANY(sqlc.arg(kinds)::text[]))
  AND (NOT sqlc.arg(has_severity)::bool OR
       (CASE severity WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END) >=
       (CASE sqlc.arg(min_severity)::text WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END))
  AND (NOT sqlc.arg(has_since)::bool OR at >= sqlc.arg(since)::timestamptz)
  AND (NOT sqlc.arg(has_cursor)::bool OR (at, id) < (sqlc.arg(before_at)::timestamptz, sqlc.arg(before_id)::uuid))
ORDER BY at DESC, id DESC
LIMIT sqlc.arg(page_limit)::int;

-- name: EventDeliveries :many
-- listEvents' deliveries[] (Shared contract: EventDelivery, channelName
-- "at delivery time"). notification_deliveries.channel_id cascades on the
-- channel's own delete, so a delivery row can never outlive its channel —
-- an INNER JOIN is safe, not a LEFT JOIN.
SELECT d.event_id, d.channel_id, c.name AS channel_name, d.attempts, d.status, d.last_error, d.delivered_at
FROM notification_deliveries d
JOIN notification_channels c ON c.id = d.channel_id
WHERE d.event_id = ANY(sqlc.arg(event_ids)::uuid[])
ORDER BY d.event_id, c.name;
