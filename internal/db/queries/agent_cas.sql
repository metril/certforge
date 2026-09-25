-- name: GetActiveAgentCA :one
SELECT * FROM agent_cas WHERE status = 'active';

-- name: GetAgentCA :one
SELECT * FROM agent_cas WHERE id = $1;

-- name: LockAgentCA :one
SELECT * FROM agent_cas WHERE id = $1 FOR UPDATE;

-- name: ShareAgentCA :one
-- A shared lock: concurrent enrolments/renewals against the same CA do not
-- serialize on each other, but still conflict with Retire's FOR UPDATE.
SELECT * FROM agent_cas WHERE id = $1 FOR SHARE;

-- name: InsertAgentCA :one
INSERT INTO agent_cas (cert_der, key, not_before, not_after) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: MarkActiveAgentCARetiring :many
-- Returns the previously active CA's id (zero rows when none was active),
-- read atomically in the same transaction that marks it retiring, so a
-- concurrent Rotate can never race this one for the "previous" CA.
UPDATE agent_cas SET status = 'retiring' WHERE status = 'active' RETURNING id;

-- name: SetAgentCARetired :one
UPDATE agent_cas SET status = 'retired' WHERE id = $1 RETURNING *;

-- name: ListTrustedAgentCAs :many
SELECT id, cert_der, status, not_after FROM agent_cas WHERE status <> 'retired' ORDER BY created_at, id;

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
