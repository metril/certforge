-- name: CreateAttempt :one
INSERT INTO issuance_attempts (cert_id) VALUES ($1) RETURNING *;

-- name: SaveAttemptProgress :exec
UPDATE issuance_attempts SET steps = $2, log = $3 WHERE id = $1;

-- name: FinishAttempt :execrows
UPDATE issuance_attempts SET outcome = $2, acme_error_type = $3, retry_after = $4,
    steps = $5, log = $6, finished_at = now()
WHERE id = $1 AND outcome = 'running';

-- name: AppendAttemptLog :exec
-- Appends one line to an attempt's log after it has already finished (fix
-- round 1): the post-issuance ARI poll runs after succeed's own
-- transaction commits, and so after FinishAttempt already wrote the
-- timeline snapshot, so a failure there can only ever be appended, not
-- folded into that snapshot.
UPDATE issuance_attempts SET log = log || $2 WHERE id = $1;

-- name: ListAttempts :many
SELECT id, cert_id, started_at, finished_at, outcome, acme_error_type, retry_after, steps,
       CASE WHEN sqlc.arg(include_log)::bool THEN log ELSE '' END::text AS log
FROM issuance_attempts WHERE cert_id = sqlc.arg(cert_id) ORDER BY started_at DESC LIMIT sqlc.arg(row_limit);

-- name: GetAttempt :one
SELECT * FROM issuance_attempts WHERE id = $1 AND cert_id = $2;

-- name: FailStaleAttempts :execrows
UPDATE issuance_attempts SET outcome = 'failed', finished_at = now(),
    log = log || 'attempt interrupted (server restart or job timeout)' || E'\n'
WHERE outcome = 'running' AND started_at < $1;

-- name: InsertManualPending :exec
INSERT INTO manual_dns_pending (attempt_id, cert_id, domain, fqdn, value, ttl, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListManualPending :many
SELECT * FROM manual_dns_pending WHERE cert_id = $1 AND confirmed_at IS NULL AND expires_at > now() ORDER BY fqdn, value;

-- name: ConfirmManualPending :execrows
UPDATE manual_dns_pending SET confirmed_at = now()
WHERE cert_id = $1 AND confirmed_at IS NULL AND expires_at > now();

-- name: PruneExpiredManualPending :execrows
DELETE FROM manual_dns_pending WHERE confirmed_at IS NULL AND expires_at < now();

-- name: ManualAllConfirmed :one
SELECT (count(*) > 0 AND count(*) FILTER (WHERE confirmed_at IS NULL) = 0)::boolean AS confirmed
FROM manual_dns_pending WHERE attempt_id = $1;

-- name: DeleteManualPending :exec
DELETE FROM manual_dns_pending WHERE attempt_id = $1;

-- name: PruneIssuanceAttempts :execrows
-- Deletes at most batch_limit finished attempts started before the cutoff,
-- always sparing a certificate's newest keep_recent attempts (however old)
-- and any attempt still running.
DELETE FROM issuance_attempts
WHERE id IN (
  SELECT ranked.id FROM (
    SELECT a.id, a.outcome, a.started_at,
           row_number() OVER (PARTITION BY a.cert_id ORDER BY a.started_at DESC, a.id DESC) AS rn
    FROM issuance_attempts a
  ) AS ranked
  WHERE ranked.outcome <> 'running' AND ranked.started_at < @before::timestamptz
    AND ranked.rn > @keep_recent::int
  LIMIT @batch_limit::int
);
