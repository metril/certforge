-- name: LastAuditHash :one
SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1;

-- name: LastAuditEvent :one
SELECT id, hash FROM audit_events ORDER BY id DESC LIMIT 1;

-- name: HasAuditAnchorMarker :one
SELECT EXISTS (SELECT 1 FROM audit_events WHERE action = 'audit.anchor_initialized');

-- name: InsertAuditEvent :one
INSERT INTO audit_events (ts, actor_type, actor_id, action, resource_type, resource_id, org_id, ip, details, prev_hash, hash, hash_alg)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING id;

-- name: ListAuditEventsAsc :many
SELECT * FROM audit_events WHERE id > $1 ORDER BY id LIMIT $2;

-- name: UpdateAuditChain :exec
UPDATE audit_events SET prev_hash = $2, hash = $3, hash_alg = 'hmac-sha256' WHERE id = $1;

-- name: CountLegacyAuditEvents :one
SELECT count(*) FROM audit_events WHERE hash_alg = 'sha256';

-- name: ListAuditEvents :many
SELECT a.id, a.ts, a.actor_type, a.actor_id, a.action, a.resource_type, a.resource_id, a.org_id, a.ip, a.details,
       COALESCE(u.display_name, k.name, cl.name, '')::text AS actor_name
FROM audit_events a
LEFT JOIN users u ON u.id = CASE WHEN a.actor_type = 'user' AND pg_input_is_valid(a.actor_id, 'uuid') THEN a.actor_id::uuid END
LEFT JOIN api_keys k ON k.id = CASE WHEN a.actor_type = 'apikey' AND pg_input_is_valid(a.actor_id, 'uuid') THEN a.actor_id::uuid END
LEFT JOIN clients cl ON cl.id = CASE WHEN a.actor_type = 'agent' AND pg_input_is_valid(a.actor_id, 'uuid') THEN a.actor_id::uuid END
WHERE (NOT sqlc.arg(has_from)::bool OR a.ts >= sqlc.arg(from_ts)::timestamptz)
  AND (NOT sqlc.arg(has_to)::bool OR a.ts < sqlc.arg(to_ts)::timestamptz)
  AND (sqlc.arg(actor)::text = '' OR a.actor_id = sqlc.arg(actor)::text)
  AND (sqlc.arg(action)::text = '' OR a.action = sqlc.arg(action)::text
       OR (right(sqlc.arg(action)::text, 1) = '.' AND starts_with(a.action, sqlc.arg(action)::text)))
  AND (sqlc.arg(resource_type)::text = '' OR a.resource_type = sqlc.arg(resource_type)::text)
  AND (sqlc.arg(resource_id)::text = '' OR a.resource_id = sqlc.arg(resource_id)::text)
  AND (sqlc.arg(any_org)::bool OR a.org_id = ANY(sqlc.arg(org_ids)::uuid[]))
  AND (sqlc.arg(q)::text = '' OR position(lower(sqlc.arg(q)::text) IN lower(
        a.action || ' ' || a.resource_type || ' ' || a.resource_id || ' ' || a.actor_id || ' ' || a.ip || ' ' || a.details::text)) > 0)
  AND (NOT sqlc.arg(has_cursor)::bool OR a.id < sqlc.arg(before_id)::bigint)
ORDER BY a.id DESC
LIMIT sqlc.arg(page_limit)::int;

-- name: GetAuditEvent :one
SELECT a.id, a.ts, a.actor_type, a.actor_id, a.action, a.resource_type, a.resource_id, a.org_id, a.ip, a.details,
       COALESCE(u.display_name, k.name, cl.name, '')::text AS actor_name
FROM audit_events a
LEFT JOIN users u ON u.id = CASE WHEN a.actor_type = 'user' AND pg_input_is_valid(a.actor_id, 'uuid') THEN a.actor_id::uuid END
LEFT JOIN api_keys k ON k.id = CASE WHEN a.actor_type = 'apikey' AND pg_input_is_valid(a.actor_id, 'uuid') THEN a.actor_id::uuid END
LEFT JOIN clients cl ON cl.id = CASE WHEN a.actor_type = 'agent' AND pg_input_is_valid(a.actor_id, 'uuid') THEN a.actor_id::uuid END
WHERE a.id = sqlc.arg(id)::bigint;

-- name: CountAuditEventsCapped :one
-- Counts matching rows up to page_limit, so the caller can tell whether the
-- export cap will truncate the result without scanning past it.
SELECT count(*) FROM (
  SELECT a.id
  FROM audit_events a
  WHERE (NOT sqlc.arg(has_from)::bool OR a.ts >= sqlc.arg(from_ts)::timestamptz)
    AND (NOT sqlc.arg(has_to)::bool OR a.ts < sqlc.arg(to_ts)::timestamptz)
    AND (sqlc.arg(actor)::text = '' OR a.actor_id = sqlc.arg(actor)::text)
    AND (sqlc.arg(action)::text = '' OR a.action = sqlc.arg(action)::text
         OR (right(sqlc.arg(action)::text, 1) = '.' AND starts_with(a.action, sqlc.arg(action)::text)))
    AND (sqlc.arg(resource_type)::text = '' OR a.resource_type = sqlc.arg(resource_type)::text)
    AND (sqlc.arg(resource_id)::text = '' OR a.resource_id = sqlc.arg(resource_id)::text)
    AND (sqlc.arg(any_org)::bool OR a.org_id = ANY(sqlc.arg(org_ids)::uuid[]))
    AND (sqlc.arg(q)::text = '' OR position(lower(sqlc.arg(q)::text) IN lower(
          a.action || ' ' || a.resource_type || ' ' || a.resource_id || ' ' || a.actor_id || ' ' || a.ip || ' ' || a.details::text)) > 0)
  LIMIT sqlc.arg(page_limit)::int
) t;
