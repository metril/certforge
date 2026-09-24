-- name: LastAuditHash :one
SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1;

-- name: InsertAuditEvent :one
INSERT INTO audit_events (ts, actor_type, actor_id, action, resource_type, resource_id, org_id, ip, details, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id;

-- name: ListAuditEventsAsc :many
SELECT * FROM audit_events WHERE id > $1 ORDER BY id LIMIT $2;
