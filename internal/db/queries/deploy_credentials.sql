-- name: ListDeployCredentials :many
SELECT * FROM deploy_credentials WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetDeployCredential :one
SELECT * FROM deploy_credentials WHERE id = $1 AND org_id = $2;

-- name: LockDeployCredential :one
-- Locks the row for the duration of a delete's count-then-delete, or of a
-- rotation that resyncs dependent targets.
SELECT * FROM deploy_credentials WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- name: LockDeployCredentialKeyShare :one
-- FOR KEY SHARE counterpart to LockDeployCredential: held while attaching a
-- credential to a target so a concurrent delete waits. Not org-scoped.
SELECT id FROM deploy_credentials WHERE id = $1 FOR KEY SHARE;

-- name: CreateDeployCredential :one
INSERT INTO deploy_credentials (org_id, name, kind, public, secret_cfg, stored_secret_keys)
VALUES ($1, $2, $3, $4, $5, COALESCE(sqlc.arg(stored_secret_keys)::text[], '{}'))
RETURNING *;

-- name: UpdateDeployCredential :one
UPDATE deploy_credentials SET name = $3, public = $4, secret_cfg = $5, stored_secret_keys = COALESCE(sqlc.arg(stored_secret_keys)::text[], '{}'), updated_at = now()
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: DeleteDeployCredential :execrows
DELETE FROM deploy_credentials WHERE id = $1 AND org_id = $2;

-- name: CountDeployCredentialUsers :one
SELECT count(*)::bigint AS users FROM deploy_targets WHERE credential_id = $1 AND org_id = $2;

-- name: CountDeployCredentialUsersByOrg :many
SELECT dc.id, count(t.id)::bigint AS users
FROM deploy_credentials dc
LEFT JOIN deploy_targets t ON t.credential_id = dc.id AND t.org_id = dc.org_id
WHERE dc.org_id = $1
GROUP BY dc.id;

-- name: ListDeployCredentialDependentTargets :many
SELECT id, name, type, runs_on FROM deploy_targets
WHERE credential_id = $1 AND org_id = $2 ORDER BY lower(name), id;
