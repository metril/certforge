-- name: CreateMonitor :one
INSERT INTO external_monitors (org_id, name, host, port, sni, interval_seconds, expected_cert_id, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListMonitors :many
-- expected_certificate_name is null when expected_cert_id is null or the
-- certificate it named has since been deleted (expected_cert_id itself goes
-- NULL too then, ON DELETE SET NULL).
SELECT m.*, ec.name AS expected_certificate_name
FROM external_monitors m
LEFT JOIN certificates ec ON ec.id = m.expected_cert_id
WHERE m.org_id = $1
ORDER BY m.name;

-- name: GetMonitor :one
SELECT m.*, ec.name AS expected_certificate_name
FROM external_monitors m
LEFT JOIN certificates ec ON ec.id = m.expected_cert_id
WHERE m.id = $1 AND m.org_id = $2;

-- name: GetMonitorByID :one
-- Unscoped by org: used by the check job (CheckArgs carries only the
-- monitor id) and Service.Check (Shared contract: no orgID parameter). The
-- API's own checkMonitor confirms org ownership first via GetMonitor.
SELECT * FROM external_monitors WHERE id = $1;

-- name: CountMonitorsInOrg :one
SELECT count(*) FROM external_monitors WHERE org_id = $1;

-- name: CertificateNameInOrg :one
-- Validates a monitor's expectedCertificateId at create/update time (must be
-- a certificate of this org) and supplies Monitor.expectedCertificateName.
SELECT name FROM certificates WHERE id = $1 AND org_id = $2;

-- name: CertificateCurrentFingerprint :one
-- The org check on expectedCertificateId already ran (CertificateNameInOrg)
-- by the time Service.Check calls this; ErrNoRows here means that
-- certificate currently has no current version (ID3), reported to
-- deriveState as an empty expected fingerprint so it can never match an
-- observed leaf.
SELECT v.sha256_fp FROM certificates c
JOIN certificate_versions v ON v.id = c.current_version_id
WHERE c.id = $1;

-- name: UpdateMonitor :one
-- state/state_changed_at/next_check_at are written only when reset_state is
-- true (a CASE, not a value Go read earlier and passes back): batch-3
-- review finding 4 — passing back a Go-side snapshot of those three columns
-- overwrites a concurrent check's own CAS transition (TransitionMonitorState)
-- whenever it lands between this update's read and its write, silently
-- reverting the state it just committed and letting the next check
-- transition (and emit) a second time for the same condition. Reading
-- "state"/etc. on the right-hand side of their own CASE means Postgres
-- evaluates them from the row this UPDATE itself just locked, never from a
-- value carried in from outside the statement.
UPDATE external_monitors
SET name = $3, host = $4, port = $5, sni = $6, interval_seconds = $7, expected_cert_id = $8, enabled = $9,
    state = CASE WHEN sqlc.arg(reset_state)::bool THEN 'unknown' ELSE state END,
    state_changed_at = CASE WHEN sqlc.arg(reset_state)::bool THEN now() ELSE state_changed_at END,
    next_check_at = CASE WHEN sqlc.arg(reset_state)::bool THEN now() ELSE next_check_at END,
    updated_at = now()
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: MonitorFingerprintKnownInOrg :one
-- When a monitor has no expectedCertificateId, mismatch is judged against
-- the org as a whole (batch-3 review finding 1): the observed leaf's
-- fingerprint must match the current version of *some* certificate this
-- org already manages, or the state is mismatch. Only current versions
-- count — an old, superseded version's fingerprint no longer vouches for
-- what a monitor should currently be seeing.
SELECT EXISTS (
    SELECT 1 FROM certificates c
    JOIN certificate_versions v ON v.id = c.current_version_id
    WHERE c.org_id = $1 AND v.sha256_fp = $2
) AS known;

-- name: DeleteMonitor :execrows
DELETE FROM external_monitors WHERE id = $1 AND org_id = $2;

-- name: DueMonitorIDs :many
-- Enabled monitors whose next check is due (external_monitors_next_check),
-- for the every-minute scan (Task 9 brief).
SELECT id FROM external_monitors
WHERE enabled AND next_check_at <= now()
ORDER BY next_check_at
LIMIT $1;

-- name: TransitionMonitorState :execrows
-- The compare-and-set at the heart of R5's dedupe rule: WHERE id AND state
-- match the value Service.Check read before dialing, so two racing checks
-- of the same monitor cannot both "win" a transition — the loser's WHERE
-- no longer matches once the winner's UPDATE has committed, and it affects
-- zero rows (Deviations R5, Task 9 brief: "a compare-and-set on state").
UPDATE external_monitors
SET state = $2, state_changed_at = $3, last_checked_at = $4, next_check_at = $5,
    last_fingerprint = $6, last_not_after = $7, last_issuer = $8, last_error = $9, updated_at = now()
WHERE id = $1 AND state = sqlc.arg(old_state)::text;
