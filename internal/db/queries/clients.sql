-- name: CreateClient :one
INSERT INTO clients (org_id, site_id, name) VALUES ($1, $2, $3) RETURNING *;

-- name: GetClient :one
SELECT * FROM clients WHERE id = $1 AND org_id = $2;

-- name: GetClientByID :one
SELECT * FROM clients WHERE id = $1;

-- name: LockClient :one
SELECT * FROM clients WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- name: LockClientByID :one
SELECT * FROM clients WHERE id = $1 FOR UPDATE;

-- name: LockClientsByID :many
-- Locks the given clients FOR UPDATE in id order (a fixed order across
-- every caller, regardless of the order ids arrive in), before any
-- deployment row is written for one of their grants: render calls this
-- first, so every path that renders a deployment locks clients before
-- deployments, ruling out the client-then-deployment vs
-- deployment-then-client deadlock between a grant write and a resync.
SELECT id FROM clients WHERE id = ANY(sqlc.arg(ids)::uuid[]) ORDER BY id FOR UPDATE;

-- name: UpdateClient :one
UPDATE clients SET name = sqlc.arg(name), site_id = sqlc.narg(site_id)
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) RETURNING *;

-- name: SetClientPending :one
UPDATE clients SET status = 'pending', agent_cert_serial = '', agent_cert_not_after = NULL, agent_ca_id = NULL
WHERE id = $1 RETURNING *;

-- name: SetClientRevoked :one
UPDATE clients SET status = 'revoked' WHERE id = $1 RETURNING *;

-- name: DeleteClient :execrows
DELETE FROM clients WHERE id = $1 AND org_id = $2 AND status IN ('pending', 'revoked');

-- name: InsertEnrollmentToken :exec
INSERT INTO enrollment_tokens (client_id, token_hash, expires_at, created_by) VALUES ($1, $2, $3, $4);

-- name: DeleteUnusedEnrollmentTokens :exec
DELETE FROM enrollment_tokens WHERE client_id = $1 AND used_at IS NULL;

-- name: PendingTokens :many
SELECT client_id, expires_at FROM enrollment_tokens
WHERE client_id = ANY(sqlc.arg(ids)::uuid[]) AND used_at IS NULL AND expires_at > now();

-- name: ConsumeEnrollmentToken :one
UPDATE enrollment_tokens SET used_at = now()
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
RETURNING client_id;

-- name: ActivateClient :one
UPDATE clients SET status = 'active', agent_cert_serial = sqlc.arg(agent_cert_serial),
       agent_cert_not_after = sqlc.arg(agent_cert_not_after), agent_ca_id = sqlc.arg(agent_ca_id),
       hostname = sqlc.arg(hostname), os = sqlc.arg(os), arch = sqlc.arg(arch),
       agent_version = sqlc.arg(agent_version), last_seen = now()
WHERE id = sqlc.arg(id) RETURNING *;

-- name: RenewClientCert :one
UPDATE clients SET agent_cert_serial = sqlc.arg(agent_cert_serial), agent_cert_not_after = sqlc.arg(agent_cert_not_after),
       agent_ca_id = sqlc.arg(agent_ca_id), last_seen = now()
WHERE id = sqlc.arg(id) AND status = 'active' AND agent_cert_serial = sqlc.arg(old_serial)
RETURNING *;

-- name: ClientCounts :many
SELECT g.client_id,
       count(*)::bigint AS grants,
       count(*) FILTER (WHERE d.state = 'drift')::bigint AS drift,
       count(*) FILTER (WHERE d.state = 'failed')::bigint AS failed
FROM client_cert_grants g
LEFT JOIN deployments d ON d.grant_id = g.id
WHERE g.client_id = ANY(sqlc.arg(ids)::uuid[]) AND g.removed_at IS NULL
GROUP BY g.client_id;

-- name: ListClients :many
SELECT k.id, k.org_id, k.site_id, k.name, k.status, k.agent_cert_serial, k.agent_cert_not_after, k.agent_ca_id,
       k.hostname, k.os, k.arch, k.agent_version, k.capabilities, k.last_seen, k.desired_revision,
       k.applied_revision, k.created_at, k.sort_key
FROM (
  SELECT c.*, (CASE sqlc.arg(sort)::text
      WHEN 'status' THEN c.status
      WHEN 'lastSeen' THEN COALESCE(to_char(c.last_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'), '')
      ELSE lower(c.name) END)::text AS sort_key
  FROM clients c
  WHERE c.org_id = ANY(sqlc.arg(org_ids)::uuid[])
    AND (sqlc.narg(site_id)::uuid IS NULL OR c.site_id = sqlc.narg(site_id)::uuid)
    AND (sqlc.arg(status)::text = '' OR c.status = sqlc.arg(status)::text)
    AND (sqlc.arg(q)::text = '' OR position(sqlc.arg(q)::text IN lower(c.name || ' ' || c.hostname)) > 0)
) k
WHERE NOT sqlc.arg(has_cursor)::bool
   OR (sqlc.arg(descending)::bool AND (k.sort_key, k.id) < (sqlc.arg(after_key)::text, sqlc.arg(after_id)::uuid))
   OR (NOT sqlc.arg(descending)::bool AND (k.sort_key, k.id) > (sqlc.arg(after_key)::text, sqlc.arg(after_id)::uuid))
ORDER BY
  CASE WHEN sqlc.arg(descending)::bool THEN k.sort_key END DESC,
  CASE WHEN sqlc.arg(descending)::bool THEN k.id END DESC,
  CASE WHEN NOT sqlc.arg(descending)::bool THEN k.sort_key END,
  CASE WHEN NOT sqlc.arg(descending)::bool THEN k.id END
LIMIT sqlc.arg(page_limit)::int;
