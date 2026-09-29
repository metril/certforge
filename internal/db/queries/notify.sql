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
