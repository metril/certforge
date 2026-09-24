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

-- name: ListCertificates :many
SELECT * FROM certificates WHERE org_id = $1 ORDER BY name;

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

-- name: MarkCertificateIssued :exec
UPDATE certificates SET status = 'active', current_version_id = $2, next_renew_at = $3,
    failure_count = 0, last_error = '', updated_at = now()
WHERE id = $1;

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
