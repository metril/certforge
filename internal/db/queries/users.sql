-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: GetLocalAdmin :one
SELECT * FROM users WHERE local_password_hash IS NOT NULL LIMIT 1;

-- name: CreateLocalAdmin :one
INSERT INTO users (display_name, local_password_hash)
VALUES ('Local admin', sqlc.arg(hash)::text)
RETURNING *;

-- name: SetLocalPasswordHash :exec
UPDATE users SET local_password_hash = sqlc.arg(hash)::text WHERE id = sqlc.arg(id);

-- name: TouchUserLogin :exec
UPDATE users SET last_login = now() WHERE id = $1;

-- name: SetUserDisabled :exec
UPDATE users SET disabled = $2 WHERE id = $1;
