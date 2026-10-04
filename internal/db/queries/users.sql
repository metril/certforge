-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserForUpdate :one
-- Locks the row so its current state (before/after an update) is accurate
-- against a concurrent PATCH of the same user.
SELECT * FROM users WHERE id = $1 FOR UPDATE;

-- name: GetLocalAdmin :one
SELECT * FROM users WHERE local_password_hash IS NOT NULL LIMIT 1;

-- name: CreateLocalAdmin :one
INSERT INTO users (display_name, local_password_hash)
VALUES ('Local admin', sqlc.arg(hash)::text)
RETURNING *;

-- name: SetLocalPasswordHash :exec
UPDATE users SET local_password_hash = sqlc.arg(hash)::text WHERE id = sqlc.arg(id);

-- name: RehashLocalPassword :execrows
UPDATE users SET local_password_hash = sqlc.arg(new_hash)::text
WHERE id = sqlc.arg(id) AND local_password_hash = sqlc.arg(old_hash)::text;

-- name: TouchUserLogin :exec
UPDATE users SET last_login = now() WHERE id = $1;

-- name: SetUserDisabled :exec
UPDATE users SET disabled = $2 WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM users ORDER BY lower(display_name), id;

-- name: UpsertOIDCUser :one
INSERT INTO users (oidc_issuer, oidc_sub, email, display_name, oidc_groups)
VALUES (sqlc.arg(issuer)::text, sqlc.arg(subject)::text, sqlc.narg(email), sqlc.arg(display_name)::text, sqlc.arg(groups)::text[])
ON CONFLICT (oidc_issuer, oidc_sub) DO UPDATE
SET email = EXCLUDED.email, display_name = EXCLUDED.display_name, oidc_groups = EXCLUDED.oidc_groups
RETURNING *;
