-- name: CreateSession :one
INSERT INTO sessions (id, user_id, csrf, expires_at) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: GetActiveSession :one
SELECT * FROM sessions WHERE id = sqlc.arg(id) AND expires_at > sqlc.arg(now)::timestamptz;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at <= sqlc.arg(now)::timestamptz;
