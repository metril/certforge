-- name: GetOrgIssuanceDefaults :one
SELECT config FROM issuance_defaults WHERE org_id = $1;

-- name: UpsertOrgIssuanceDefaults :exec
INSERT INTO issuance_defaults (org_id, config) VALUES ($1, $2)
ON CONFLICT (org_id) DO UPDATE SET config = EXCLUDED.config, updated_at = now();

-- name: CreateCertificate :one
INSERT INTO certificates (org_id, name, common_name, sans, verification_rules, overrides, next_renew_at)
VALUES ($1, $2, $3, $4, $5, $6, now())
RETURNING *;

-- name: GetCertificate :one
SELECT * FROM certificates WHERE id = $1 AND org_id = $2;

-- name: GetCertificateByID :one
SELECT * FROM certificates WHERE id = $1;

-- name: GetCertificateForUpdate :one
-- Locks the row for the duration of UpdateCertificate's read-compute-write,
-- so a concurrent update cannot compute reissue from names that are already
-- stale by the time this transaction commits.
SELECT * FROM certificates WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- The 8 queries below back ListCertificates' keyset-paged listing (one per
-- supported sort field x direction). They share the same q/status filter
-- and cursor shape:
--   - status_filter/q_filter: '' means "no filter"; q is a case-insensitive
--     substring match against the certificate's name, common name, and any
--     SAN (mirrors the old in-memory listParams.matches).
--   - has_cursor/last_key/last_id: has_cursor false means "first page";
--     otherwise the predicate resumes strictly after (last_key, last_id) in
--     the query's sort order, which is why every ORDER BY also breaks ties
--     on id.
--   - page_limit is the caller's page size + 1, so the handler can detect
--     whether there is a next page without a second round trip.
-- A nullable sort column (next_renew_at, and not_after via the current
-- version, which is null for a pending certificate) is coalesced to the
-- X.509 "no well-defined expiration" sentinel (9999-12-31T23:59:59Z, well
-- outside any real certificate lifetime) so it sorts last ascending and
-- first descending — Postgres's own NULLS LAST/NULLS FIRST defaults —
-- without the keyset predicate's row comparison ever seeing a NULL, which
-- would otherwise silently exclude every subsequent row.

-- name: ListCertificatesPageByNameAsc :many
SELECT c.*, c.name AS sort_key FROM certificates c
WHERE c.org_id = ANY(sqlc.arg(org_ids)::uuid[])
  AND (sqlc.arg(status_filter)::text = '' OR c.status = sqlc.arg(status_filter))
  AND (sqlc.arg(q_filter)::text = ''
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.name)) > 0
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.common_name)) > 0
       OR EXISTS (SELECT 1 FROM unnest(c.sans) AS s WHERE position(lower(sqlc.arg(q_filter)::text) in lower(s)) > 0))
  AND (NOT sqlc.arg(has_cursor)::bool OR (c.name, c.id) > (sqlc.arg(last_key)::text, sqlc.arg(last_id)::uuid))
ORDER BY c.name ASC, c.id ASC
LIMIT sqlc.arg(page_limit)::int;

-- name: ListCertificatesPageByNameDesc :many
SELECT c.*, c.name AS sort_key FROM certificates c
WHERE c.org_id = ANY(sqlc.arg(org_ids)::uuid[])
  AND (sqlc.arg(status_filter)::text = '' OR c.status = sqlc.arg(status_filter))
  AND (sqlc.arg(q_filter)::text = ''
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.name)) > 0
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.common_name)) > 0
       OR EXISTS (SELECT 1 FROM unnest(c.sans) AS s WHERE position(lower(sqlc.arg(q_filter)::text) in lower(s)) > 0))
  AND (NOT sqlc.arg(has_cursor)::bool OR (c.name, c.id) < (sqlc.arg(last_key)::text, sqlc.arg(last_id)::uuid))
ORDER BY c.name DESC, c.id DESC
LIMIT sqlc.arg(page_limit)::int;

-- name: ListCertificatesPageByStatusAsc :many
SELECT c.*, c.status AS sort_key FROM certificates c
WHERE c.org_id = ANY(sqlc.arg(org_ids)::uuid[])
  AND (sqlc.arg(status_filter)::text = '' OR c.status = sqlc.arg(status_filter))
  AND (sqlc.arg(q_filter)::text = ''
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.name)) > 0
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.common_name)) > 0
       OR EXISTS (SELECT 1 FROM unnest(c.sans) AS s WHERE position(lower(sqlc.arg(q_filter)::text) in lower(s)) > 0))
  AND (NOT sqlc.arg(has_cursor)::bool OR (c.status, c.id) > (sqlc.arg(last_key)::text, sqlc.arg(last_id)::uuid))
ORDER BY c.status ASC, c.id ASC
LIMIT sqlc.arg(page_limit)::int;

-- name: ListCertificatesPageByStatusDesc :many
SELECT c.*, c.status AS sort_key FROM certificates c
WHERE c.org_id = ANY(sqlc.arg(org_ids)::uuid[])
  AND (sqlc.arg(status_filter)::text = '' OR c.status = sqlc.arg(status_filter))
  AND (sqlc.arg(q_filter)::text = ''
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.name)) > 0
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.common_name)) > 0
       OR EXISTS (SELECT 1 FROM unnest(c.sans) AS s WHERE position(lower(sqlc.arg(q_filter)::text) in lower(s)) > 0))
  AND (NOT sqlc.arg(has_cursor)::bool OR (c.status, c.id) < (sqlc.arg(last_key)::text, sqlc.arg(last_id)::uuid))
ORDER BY c.status DESC, c.id DESC
LIMIT sqlc.arg(page_limit)::int;

-- name: ListCertificatesPageByNextRenewAtAsc :many
SELECT c.*, COALESCE(c.next_renew_at, TIMESTAMPTZ '9999-12-31 23:59:59+00') AS sort_key FROM certificates c
WHERE c.org_id = ANY(sqlc.arg(org_ids)::uuid[])
  AND (sqlc.arg(status_filter)::text = '' OR c.status = sqlc.arg(status_filter))
  AND (sqlc.arg(q_filter)::text = ''
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.name)) > 0
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.common_name)) > 0
       OR EXISTS (SELECT 1 FROM unnest(c.sans) AS s WHERE position(lower(sqlc.arg(q_filter)::text) in lower(s)) > 0))
  AND (NOT sqlc.arg(has_cursor)::bool
       OR (COALESCE(c.next_renew_at, TIMESTAMPTZ '9999-12-31 23:59:59+00'), c.id) > (sqlc.arg(last_key)::timestamptz, sqlc.arg(last_id)::uuid))
ORDER BY sort_key ASC, c.id ASC
LIMIT sqlc.arg(page_limit)::int;

-- name: ListCertificatesPageByNextRenewAtDesc :many
SELECT c.*, COALESCE(c.next_renew_at, TIMESTAMPTZ '9999-12-31 23:59:59+00') AS sort_key FROM certificates c
WHERE c.org_id = ANY(sqlc.arg(org_ids)::uuid[])
  AND (sqlc.arg(status_filter)::text = '' OR c.status = sqlc.arg(status_filter))
  AND (sqlc.arg(q_filter)::text = ''
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.name)) > 0
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.common_name)) > 0
       OR EXISTS (SELECT 1 FROM unnest(c.sans) AS s WHERE position(lower(sqlc.arg(q_filter)::text) in lower(s)) > 0))
  AND (NOT sqlc.arg(has_cursor)::bool
       OR (COALESCE(c.next_renew_at, TIMESTAMPTZ '9999-12-31 23:59:59+00'), c.id) < (sqlc.arg(last_key)::timestamptz, sqlc.arg(last_id)::uuid))
ORDER BY sort_key DESC, c.id DESC
LIMIT sqlc.arg(page_limit)::int;

-- name: ListCertificatesPageByNotAfterAsc :many
SELECT c.*, COALESCE(v.not_after, TIMESTAMPTZ '9999-12-31 23:59:59+00') AS sort_key
FROM certificates c
LEFT JOIN certificate_versions v ON v.id = c.current_version_id
WHERE c.org_id = ANY(sqlc.arg(org_ids)::uuid[])
  AND (sqlc.arg(status_filter)::text = '' OR c.status = sqlc.arg(status_filter))
  AND (sqlc.arg(q_filter)::text = ''
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.name)) > 0
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.common_name)) > 0
       OR EXISTS (SELECT 1 FROM unnest(c.sans) AS s WHERE position(lower(sqlc.arg(q_filter)::text) in lower(s)) > 0))
  AND (NOT sqlc.arg(has_cursor)::bool
       OR (COALESCE(v.not_after, TIMESTAMPTZ '9999-12-31 23:59:59+00'), c.id) > (sqlc.arg(last_key)::timestamptz, sqlc.arg(last_id)::uuid))
ORDER BY sort_key ASC, c.id ASC
LIMIT sqlc.arg(page_limit)::int;

-- name: ListCertificatesPageByNotAfterDesc :many
SELECT c.*, COALESCE(v.not_after, TIMESTAMPTZ '9999-12-31 23:59:59+00') AS sort_key
FROM certificates c
LEFT JOIN certificate_versions v ON v.id = c.current_version_id
WHERE c.org_id = ANY(sqlc.arg(org_ids)::uuid[])
  AND (sqlc.arg(status_filter)::text = '' OR c.status = sqlc.arg(status_filter))
  AND (sqlc.arg(q_filter)::text = ''
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.name)) > 0
       OR position(lower(sqlc.arg(q_filter)::text) in lower(c.common_name)) > 0
       OR EXISTS (SELECT 1 FROM unnest(c.sans) AS s WHERE position(lower(sqlc.arg(q_filter)::text) in lower(s)) > 0))
  AND (NOT sqlc.arg(has_cursor)::bool
       OR (COALESCE(v.not_after, TIMESTAMPTZ '9999-12-31 23:59:59+00'), c.id) < (sqlc.arg(last_key)::timestamptz, sqlc.arg(last_id)::uuid))
ORDER BY sort_key DESC, c.id DESC
LIMIT sqlc.arg(page_limit)::int;

-- name: UpdateCertificate :one
UPDATE certificates SET name = $3, common_name = $4, sans = $5, verification_rules = $6,
    overrides = $7, next_renew_at = CASE WHEN sqlc.arg(reissue)::bool THEN now() ELSE next_renew_at END,
    updated_at = now()
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: DeleteCertificate :execrows
DELETE FROM certificates WHERE id = $1 AND org_id = $2;

-- name: ListDueCertificateIDs :many
SELECT id FROM certificates
WHERE next_renew_at IS NOT NULL AND next_renew_at <= now()
ORDER BY next_renew_at
LIMIT $1;

-- name: MarkCertificateIssued :one
-- issued_common_name/issued_sans are the names the version being stored
-- actually covers (as captured when the attempt started). If the row's
-- current common_name/sans no longer match — an operator changed the
-- certificate's names while this attempt was running — the CASE keeps
-- next_renew_at at now() instead of the normal renewal date
-- (next_renew_at), so the scheduler reissues for the new names within its
-- next sweep instead of losing the edit for the certificate's whole
-- lifetime. The comparison and the write happen in one statement (no
-- separate FOR UPDATE read) so there is no window for a concurrent name
-- change to race between reading and writing.
UPDATE certificates SET status = 'active', current_version_id = $2,
    next_renew_at = CASE WHEN common_name = sqlc.arg(issued_common_name) AND sans = sqlc.arg(issued_sans)
                          THEN sqlc.arg(next_renew_at)::timestamptz ELSE now() END,
    failure_count = 0, last_error = '', updated_at = now()
WHERE id = $1
RETURNING next_renew_at;

-- name: MarkCertificateFailed :exec
UPDATE certificates SET status = $2, failure_count = $3, last_error = $4, next_renew_at = $5, updated_at = now()
WHERE id = $1;

-- name: MarkExpiredCertificates :execrows
UPDATE certificates c SET status = 'expired', updated_at = now()
FROM certificate_versions v
WHERE v.id = c.current_version_id AND c.status IN ('active', 'failed') AND v.not_after < now();

-- name: InsertCertificateVersion :one
INSERT INTO certificate_versions (cert_id, serial, not_before, not_after, sha256_fp, key_type, leaf_der, chain_der, private_key)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, cert_id, serial, not_before, not_after, sha256_fp, key_type, source, revoked_at, created_at;

-- name: ListCertificateVersions :many
SELECT id, cert_id, serial, not_before, not_after, sha256_fp, key_type, source, revoked_at, created_at
FROM certificate_versions WHERE cert_id = $1 ORDER BY created_at DESC;

-- name: GetCertificateVersion :one
SELECT * FROM certificate_versions WHERE id = $1 AND cert_id = $2;

-- name: ListCertificateVersionsByIDs :many
-- Batch-loads version metadata for a set of ids in one round trip, so a
-- certificate list page can render every item's currentVersion without one
-- query per certificate.
SELECT id, cert_id, serial, not_before, not_after, sha256_fp, key_type, source, revoked_at, created_at
FROM certificate_versions WHERE id = ANY($1::uuid[]);
