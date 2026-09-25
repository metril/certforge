-- name: GetActiveAgentCA :one
SELECT * FROM agent_cas WHERE status = 'active';

-- name: GetAgentCA :one
SELECT * FROM agent_cas WHERE id = $1;

-- name: LockAgentCA :one
SELECT * FROM agent_cas WHERE id = $1 FOR UPDATE;

-- name: InsertAgentCA :one
INSERT INTO agent_cas (cert_der, key, not_before, not_after) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: MarkActiveAgentCARetiring :exec
UPDATE agent_cas SET status = 'retiring' WHERE status = 'active';

-- name: SetAgentCARetired :one
UPDATE agent_cas SET status = 'retired' WHERE id = $1 RETURNING *;

-- name: ListTrustedAgentCAs :many
SELECT * FROM agent_cas WHERE status <> 'retired' ORDER BY created_at, id;

-- name: GetOldestTrustedAgentCA :one
SELECT * FROM agent_cas WHERE status <> 'retired' ORDER BY created_at, id LIMIT 1;

-- name: ListAgentCAs :many
SELECT a.id, a.cert_der, a.status, a.created_at,
       (SELECT count(*) FROM clients c
         WHERE c.agent_ca_id = a.id AND c.status = 'active' AND c.agent_cert_not_after > now())::bigint AS active_client_certs
FROM agent_cas a ORDER BY a.created_at DESC, a.id;

-- name: CountActiveClientCertsForCA :one
SELECT count(*)::bigint FROM clients
WHERE agent_ca_id = sqlc.arg(ca_id)::uuid AND status = 'active' AND agent_cert_not_after > now();
