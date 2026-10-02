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

-- name: CertificatesUsingClient :many
-- Certificates whose own verification rules reference clientId, plus the
-- literal "org default rules" when this org's issuance_defaults rules do
-- (a default rule names no single certificate of its own), plus "global
-- default rules" when the cross-org global issuance_defaults settings
-- section does (settings.key = 'section.issuance_defaults', the same JSON
-- shape as issuance_defaults.config: see settings.SectionKey and
-- issuance.SettingsKey); DeleteClient 409s naming these instead of
-- deleting a client an http-01/tls-alpn-01 rule still relies on.
SELECT name FROM (
  SELECT c.name AS name FROM certificates c
  WHERE c.org_id = sqlc.arg(org_id)
    AND (c.verification_rules @> jsonb_build_array(jsonb_build_object('clientId', sqlc.arg(client_id)::uuid::text))
      OR c.overrides->'verificationRules' @> jsonb_build_array(jsonb_build_object('clientId', sqlc.arg(client_id)::uuid::text)))
  UNION ALL
  SELECT 'org default rules' AS name
  WHERE EXISTS (SELECT 1 FROM issuance_defaults d WHERE d.org_id = sqlc.arg(org_id)
    AND d.config->'verificationRules' @> jsonb_build_array(jsonb_build_object('clientId', sqlc.arg(client_id)::uuid::text)))
  UNION ALL
  SELECT 'global default rules' AS name
  WHERE EXISTS (SELECT 1 FROM settings s WHERE s.key = 'section.issuance_defaults'
    AND s.value->'verificationRules' @> jsonb_build_array(jsonb_build_object('clientId', sqlc.arg(client_id)::uuid::text)))
) u ORDER BY lower(name) LIMIT 6;

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

-- name: CurrentVersionsForCerts :many
-- Cert id -> current_version_id for a layout's extra certificates, used to
-- render them (agents.Service.render) and to detect drift
-- (StaleDeploymentGrantIDs mirrors this same lookup in SQL).
SELECT id, current_version_id FROM certificates WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: ListDueCertificateIDs :many
-- managed is redundant with next_renew_at IS NOT NULL (the
-- certificates_unmanaged_no_renewal CHECK constraint keeps an unmanaged
-- row's next_renew_at NULL), but it says outright, at the query that
-- decides what gets (re)issued, that an unmanaged certificate is never due.
SELECT id FROM certificates
WHERE managed AND next_renew_at IS NOT NULL AND next_renew_at <= now()
ORDER BY next_renew_at
LIMIT $1;

-- name: CreateExternalCertificate :one
-- Creates an unmanaged (imported or uploaded) certificate row: no CA, no
-- verification rules of its own, and next_renew_at left to the caller
-- (NULL for every unmanaged certificate; the certificates_unmanaged_no_renewal
-- CHECK constraint enforces it). Unlike CreateCertificate this does not
-- hard-code next_renew_at to now(): a managed certificate is always due
-- immediately, but an unmanaged one is never due at all. The caller passes
-- the same common_name/sans/status it is about to write again via
-- SetCurrentVersion right after (this insert must satisfy the row's own
-- NOT NULL columns), and SetCurrentVersion is also the query used for
-- every later uploadCertificateVersion, so the two stay in step. A
-- duplicate (org_id, name) is the same unique_violation CreateCertificate
-- can raise; the caller (issuance.Service.UploadCertificate) maps it to a
-- 409, not CreateCertificate's usual 422.
INSERT INTO certificates (org_id, name, common_name, sans, overrides, managed, status, next_renew_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: SetCurrentVersion :one
-- Attaches a newly stored version to a certificate and refreshes the
-- fields that follow from it: names (an uploaded/imported version can
-- cover different names than the certificate's current definition),
-- status (active or expired, by the new version's own validity) and
-- next_renew_at (always NULL for an unmanaged certificate; UploadCertificate/
-- UploadVersion always pass NULL). Used both right after
-- CreateExternalCertificate (the certificate's first version) and for
-- every later uploadCertificateVersion on the same certificate.
UPDATE certificates SET common_name = $3, sans = $4, current_version_id = $2,
    status = $5, next_renew_at = $6, updated_at = now()
WHERE id = $1
RETURNING *;

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
-- ari_window_start/end/checked_at/retry_after are cleared here too (fix
-- round 1): they cache ARI for the version that was current before this
-- write, so a new current_version_id must not keep showing that stale
-- window on the API until the next poll happens to overwrite it (up to 6h
-- away).
UPDATE certificates SET status = 'active', current_version_id = $2,
    next_renew_at = CASE WHEN common_name = sqlc.arg(issued_common_name) AND sans = sqlc.arg(issued_sans)
                          THEN sqlc.arg(next_renew_at)::timestamptz ELSE now() END,
    failure_count = 0, last_error = '', updated_at = now(),
    ari_window_start = NULL, ari_window_end = NULL, ari_checked_at = NULL, ari_retry_after = NULL
WHERE id = $1
RETURNING next_renew_at;

-- name: MarkCertificateFailed :exec
UPDATE certificates SET status = $2, failure_count = $3, last_error = $4, next_renew_at = $5, updated_at = now()
WHERE id = $1;

-- name: ListARIDue :many
-- Certificates due for an ACME Renewal Information poll (ARIPollWorker):
-- managed, with a stored current version, status active, and either never
-- polled or past their ari_retry_after. Paginated with a plain id keyset
-- (fix round 1): PollDue walks every page in one run, not just a single
-- LIMIT — a certificate skipped (useAri off, no CA recorded) or erroring
-- also gets its own ari_retry_after bumped (BumpARIRetryAfter), so it
-- cannot crowd out certificates ordered after it on the next page, or on
-- the next run. Whether the certificate's effective renewPolicy.useAri is
-- actually set is resolved separately in Go (Store.EffectiveFor merges
-- three JSON levels, not expressible here).
SELECT * FROM certificates
WHERE managed AND current_version_id IS NOT NULL AND status = 'active'
  AND (ari_retry_after IS NULL OR ari_retry_after <= now())
  AND (NOT sqlc.arg(has_cursor)::bool OR id > sqlc.arg(last_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(page_limit)::int;

-- name: SetARIWindow :exec
-- Stores a freshly fetched ARI window, conditional on current_version_id
-- still matching the version the window was fetched for: a concurrent
-- reissue mid-poll must not attach a stale window to the certificate's new
-- version.
UPDATE certificates SET ari_window_start = $3, ari_window_end = $4, ari_checked_at = $5, ari_retry_after = $6
WHERE id = $1 AND current_version_id = $2;

-- name: BumpARIRetryAfter :exec
-- Sets only ari_retry_after, leaving any cached window untouched (fix
-- round 1): used when a poll is skipped (useAri off, no CA recorded for
-- the current version) or errors before a window was actually fetched, so
-- the certificate does not occupy ListARIDue's next page, or the next
-- run's first page, forever. Conditional on current_version_id, same as
-- SetARIWindow.
UPDATE certificates SET ari_retry_after = $3
WHERE id = $1 AND current_version_id = $2;

-- name: LowerNextRenewAt :exec
-- Moves next_renew_at earlier only (LEAST(), so a later ARI window can
-- never move it back out), only for a certificate whose last attempt did
-- not fail, and only while current_version_id still matches (see
-- SetARIWindow's comment).
UPDATE certificates SET next_renew_at = LEAST(next_renew_at, $3), updated_at = now()
WHERE id = $1 AND current_version_id = $2 AND failure_count = 0;

-- name: MarkExpiredCertificates :execrows
UPDATE certificates c SET status = 'expired', updated_at = now()
FROM certificate_versions v
WHERE v.id = c.current_version_id AND c.status IN ('active', 'failed') AND v.not_after < now();

-- name: InsertCertificateVersion :one
-- private_key is nullable (a keyless import/upload stores NULL); has_key
-- reports whether one is stored without ever selecting the sealed bytes
-- themselves into a metadata-only row.
INSERT INTO certificate_versions (cert_id, serial, not_before, not_after, sha256_fp, key_type, leaf_der, chain_der, private_key, source, ca_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id, cert_id, serial, not_before, not_after, sha256_fp, key_type, source, ca_id, (private_key IS NOT NULL)::boolean AS has_key, revoked_at, created_at;

-- name: ListCertificateVersions :many
SELECT id, cert_id, serial, not_before, not_after, sha256_fp, key_type, source, ca_id, (private_key IS NOT NULL)::boolean AS has_key, revoked_at, created_at
FROM certificate_versions WHERE cert_id = $1 ORDER BY created_at DESC;

-- name: GetCertificateVersion :one
SELECT * FROM certificate_versions WHERE id = $1 AND cert_id = $2;

-- name: LockCertificateVersionForUpdate :one
-- Locks one version for the duration of RevokeVersion's read-check-write
-- (issuance.Store.RevokeVersion), so a concurrent revoke of the same
-- version serializes instead of both reading revoked_at IS NULL and racing
-- the update.
SELECT * FROM certificate_versions WHERE id = $1 AND cert_id = $2 FOR UPDATE;

-- name: SetCertificateVersionRevoked :one
UPDATE certificate_versions SET revoked_at = $3
WHERE id = $1 AND cert_id = $2
RETURNING id, cert_id, serial, not_before, not_after, sha256_fp, key_type, source, ca_id, (private_key IS NOT NULL)::boolean AS has_key, revoked_at, created_at;

-- name: ListCertificateVersionsByIDs :many
-- Batch-loads version metadata for a set of ids in one round trip, so a
-- certificate list page can render every item's currentVersion without one
-- query per certificate.
SELECT id, cert_id, serial, not_before, not_after, sha256_fp, key_type, source, ca_id, (private_key IS NOT NULL)::boolean AS has_key, revoked_at, created_at
FROM certificate_versions WHERE id = ANY($1::uuid[]);

-- name: ListCertificateIssuerRefs :many
-- Everything needed to resolve which CA, account and DNS credentials each
-- certificate in one org uses. No LIMIT: the system map counts issuer use
-- over every certificate. Same org filter as the certificate list.
SELECT c.id, c.verification_rules, c.overrides FROM certificates c
WHERE c.org_id = sqlc.arg(org_id)::uuid;
