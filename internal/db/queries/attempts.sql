-- name: CreateAttempt :one
INSERT INTO issuance_attempts (cert_id) VALUES ($1) RETURNING *;

-- name: SaveAttemptProgress :exec
UPDATE issuance_attempts SET steps = $2, log = $3 WHERE id = $1;

-- name: FinishAttempt :execrows
UPDATE issuance_attempts SET outcome = $2, acme_error_type = $3, retry_after = $4,
    steps = $5, log = $6, finished_at = now()
WHERE id = $1 AND outcome = 'running';

-- name: ListAttempts :many
SELECT * FROM issuance_attempts WHERE cert_id = $1 ORDER BY started_at DESC LIMIT $2;

-- name: FailStaleAttempts :execrows
UPDATE issuance_attempts SET outcome = 'failed', finished_at = now(),
    log = log || 'attempt interrupted (server restart or job timeout)' || E'\n'
WHERE outcome = 'running' AND started_at < $1;

-- name: InsertManualPending :exec
INSERT INTO manual_dns_pending (attempt_id, cert_id, domain, fqdn, value, ttl, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListManualPending :many
SELECT * FROM manual_dns_pending WHERE cert_id = $1 AND confirmed_at IS NULL ORDER BY fqdn, value;

-- name: ConfirmManualPending :execrows
UPDATE manual_dns_pending SET confirmed_at = now()
WHERE cert_id = $1 AND confirmed_at IS NULL AND expires_at > now();

-- name: ManualAllConfirmed :one
SELECT (count(*) > 0 AND count(*) FILTER (WHERE confirmed_at IS NULL) = 0)::boolean AS confirmed
FROM manual_dns_pending WHERE attempt_id = $1;

-- name: DeleteManualPending :exec
DELETE FROM manual_dns_pending WHERE attempt_id = $1;
