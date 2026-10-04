-- name: CreateAPIKey :one
INSERT INTO api_keys (name, prefix, secret_hash, scopes, org_id, created_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: GetAPIKey :one
SELECT * FROM api_keys WHERE id = $1;

-- name: GetAPIKeyByPrefix :one
SELECT * FROM api_keys WHERE prefix = $1;

-- name: ListAPIKeys :many
SELECT k.*, u.display_name AS created_by_name
FROM api_keys k JOIN users u ON u.id = k.created_by
WHERE sqlc.narg(org_id)::uuid IS NULL OR k.org_id = sqlc.narg(org_id)
ORDER BY k.created_at DESC, k.id;

-- name: RevokeAPIKey :execrows
UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: TouchAPIKey :exec
UPDATE api_keys SET last_used_at = now()
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- name: ListRoleBindingsForAPIKey :many
SELECT * FROM role_bindings WHERE subject_type = 'apikey' AND subject = $1 ORDER BY created_at, id;

-- name: CountActiveAPIKeysByCreator :one
SELECT count(*) FROM api_keys
WHERE created_by = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now());
