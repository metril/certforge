-- name: InsertLedgerRow :exec
-- Records one rate-ledger event. new_order rows carry registered_domain=''
-- and names_hash=''; cert_issued rows carry one row per registered domain
-- of the certificate (same names_hash and cert_id on every row); failed_
-- validation rows carry registered_domain alone.
INSERT INTO rate_ledger (ca_id, kind, registered_domain, names_hash, cert_id, at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: InsertLedgerReservation :exec
-- InsertLedgerRow for ReserveLedger: attempt_id ties the row to one issue
-- attempt. reserved_until is set for cert_issued rows (a reservation that
-- stops counting when it passes) and NULL for new_order rows (the order is
-- sent, so it always counts).
INSERT INTO rate_ledger (ca_id, kind, registered_domain, names_hash, cert_id, at, attempt_id, reserved_until)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: LedgerAttemptReserved :one
-- True when ReserveLedger already ran for the attempt (a retry of it must
-- not count twice).
SELECT EXISTS (SELECT 1 FROM rate_ledger WHERE attempt_id = $1);

-- name: ConfirmLedgerReservation :execrows
-- Turns the attempt's cert_issued reservations into plain rows, dated at
-- issue time. 0 rows: nothing was reserved (private CA, or the reservation
-- was pruned), the caller inserts instead.
UPDATE rate_ledger SET reserved_until = NULL, at = $2
WHERE attempt_id = $1 AND kind = 'cert_issued' AND reserved_until IS NOT NULL;

-- name: ReleaseLedgerReservation :execrows
-- Drops the attempt's still-reserved rows; its new_order row stays.
DELETE FROM rate_ledger WHERE attempt_id = $1 AND reserved_until IS NOT NULL;

-- name: CountLedgerByDomain :one
-- Every Count*/Oldest* query skips reservations that expired before the last
-- parameter (the caller's now).
-- Counts kind's rows scoped to one registered domain (certsPerRegistered
-- DomainPerWeek, failedValidationsPerHour). CA-wide: not org-scoped. at > $4
-- (not >=), fix round 1: a row exactly window-old must not still count, or
-- a retry exactly at RetryAt (oldest+window) would wrongly see it blocked
-- again.
SELECT count(*) FROM rate_ledger
WHERE ca_id = $1 AND kind = $2 AND registered_domain = $3 AND at > $4
  AND (reserved_until IS NULL OR reserved_until > $5);

-- name: CountLedgerByNames :one
-- Counts cert_issued rows for one names_hash, restricted to the registered
-- domain that was first (sorted) among the certificate's names, so a
-- multi-domain issuance's several per-domain rows are counted once
-- (duplicateCertsPerWeek). CA-wide: not org-scoped.
SELECT count(*) FROM rate_ledger
WHERE ca_id = $1 AND kind = $2 AND names_hash = $3 AND registered_domain = $4 AND at > $5
  AND (reserved_until IS NULL OR reserved_until > $6);

-- name: CountLedgerByCA :one
-- Counts kind's rows for the whole CA (newOrdersPer3Hours; registered_domain
-- is always '' for new_order rows).
SELECT count(*) FROM rate_ledger
WHERE ca_id = $1 AND kind = $2 AND at > $3
  AND (reserved_until IS NULL OR reserved_until > $4);

-- name: OldestLedgerByDomain :one
-- The oldest row still inside the window CountLedgerByDomain just counted;
-- its limit's RetryAt is this plus the window length. NULL when the count
-- is 0.
SELECT min(at)::timestamptz FROM rate_ledger
WHERE ca_id = $1 AND kind = $2 AND registered_domain = $3 AND at > $4
  AND (reserved_until IS NULL OR reserved_until > $5);

-- name: OldestLedgerByNames :one
-- OldestLedgerByDomain's counterpart for CountLedgerByNames.
SELECT min(at)::timestamptz FROM rate_ledger
WHERE ca_id = $1 AND kind = $2 AND names_hash = $3 AND registered_domain = $4 AND at > $5
  AND (reserved_until IS NULL OR reserved_until > $6);

-- name: OldestLedgerByCA :one
-- OldestLedgerByDomain's counterpart for CountLedgerByCA.
SELECT min(at)::timestamptz FROM rate_ledger
WHERE ca_id = $1 AND kind = $2 AND at > $3
  AND (reserved_until IS NULL OR reserved_until > $4);

-- name: PruneLedger :execrows
-- Deletes rows older than the retention cutoff (now - 30d); run by the
-- 5-minute certforge_schedule job. Also drops expired reservations (a
-- crashed worker never released its own).
DELETE FROM rate_ledger WHERE at < $1 OR (reserved_until IS NOT NULL AND reserved_until < now());

-- name: LedgerDomainsInWindow :many
-- The distinct registered domains with any rate-ledger activity in the
-- window (fix round 1: every kind, not just cert_issued — a
-- failed_validation row carries cert_id too, and a certificate that has
-- only ever failed must still be discoverable), scoped to certificates the
-- calling org owns (GetRateLedger's item scopes); new_order rows carry no
-- cert_id and so never match this join at all. The counts themselves stay
-- CA-wide (queried separately, unscoped by org).
SELECT DISTINCT rl.registered_domain FROM rate_ledger rl
JOIN certificates c ON c.id = rl.cert_id
WHERE rl.ca_id = $1 AND rl.at > $2 AND c.org_id = $3
ORDER BY rl.registered_domain;
