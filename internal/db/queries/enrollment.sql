-- name: GetEnrollmentTokenByLookup :one
SELECT id, client_id, token_hash, expires_at, used_at FROM enrollment_tokens WHERE lookup_id = $1;

-- name: ConsumeEnrollmentTokenByID :one
UPDATE enrollment_tokens SET used_at = now()
WHERE id = $1 AND used_at IS NULL AND expires_at > now()
RETURNING client_id;

-- name: InsertEnrollmentRequest :one
INSERT INTO enrollment_requests (org_id, client_id, token_id, poll_secret_hash, csr, pubkey_fp, verify_code, facts, source_ip, status, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(client_id), sqlc.arg(token_id), sqlc.arg(poll_secret_hash), sqlc.arg(csr), sqlc.arg(pubkey_fp),
        sqlc.arg(verify_code), sqlc.arg(facts), sqlc.arg(source_ip), sqlc.arg(status), sqlc.arg(expires_at))
RETURNING *;

-- name: GetEnrollmentRequestByTokenForUpdate :one
SELECT * FROM enrollment_requests WHERE token_id = $1 FOR UPDATE;

-- name: GetEnrollmentRequest :one
SELECT * FROM enrollment_requests WHERE id = $1;

-- name: LockEnrollmentRequest :one
SELECT * FROM enrollment_requests WHERE id = $1 FOR UPDATE;

-- name: RotateEnrollmentPollSecret :exec
UPDATE enrollment_requests SET poll_secret_hash = $2 WHERE id = $1;

-- name: CountPendingEnrollmentRequests :one
SELECT count(*) FROM enrollment_requests WHERE org_id = $1 AND status = 'pending' AND expires_at > $2;

-- name: ListPendingEnrollmentRequests :many
SELECT r.id, r.org_id, r.client_id, c.name AS client_name, c.site_id, r.verify_code, r.pubkey_fp, r.facts, r.source_ip,
       r.created_at, r.expires_at
FROM enrollment_requests r JOIN clients c ON c.id = r.client_id
WHERE r.org_id = ANY(sqlc.arg(org_ids)::uuid[]) AND r.status = 'pending' AND r.expires_at > sqlc.arg(now)::timestamptz
ORDER BY r.created_at, r.id;

-- name: DecideEnrollmentRequest :one
UPDATE enrollment_requests SET status = sqlc.arg(status), decided_by = sqlc.arg(decided_by), decided_at = sqlc.arg(now)::timestamptz,
       expires_at = sqlc.arg(expires_at)
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) AND status = 'pending' AND expires_at > sqlc.arg(now)::timestamptz
RETURNING *;

-- name: SetEnrollmentRequestStatus :exec
UPDATE enrollment_requests SET status = $2 WHERE id = $1;

-- name: MarkEnrollmentIssued :exec
UPDATE enrollment_requests SET status = 'issued', certificate_pem = $2 WHERE id = $1;

-- name: ExpireEnrollmentRequests :execrows
UPDATE enrollment_requests SET status = 'expired' WHERE status IN ('pending', 'approved') AND expires_at <= $1;

-- name: PruneEnrollmentRequests :execrows
DELETE FROM enrollment_requests WHERE status IN ('rejected', 'expired', 'issued') AND created_at < $1;

-- name: DeleteEnrollmentRequestsForClient :exec
DELETE FROM enrollment_requests WHERE client_id = $1;
