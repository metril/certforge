-- name: CreateDNSCredential :one
INSERT INTO dns_provider_credentials (org_id, name, provider_code, public_cfg, secret_cfg, stored_secret_keys)
VALUES ($1, $2, $3, $4, $5, COALESCE(sqlc.arg(stored_secret_keys)::text[], '{}'))
RETURNING *;

-- name: GetDNSCredential :one
SELECT * FROM dns_provider_credentials WHERE id = $1 AND org_id = $2;

-- name: DNSCredentialExists :one
-- Ignores org scope: used only to check that a credential referenced by a
-- rule in the global issuance_defaults settings section still exists.
SELECT EXISTS(SELECT 1 FROM dns_provider_credentials WHERE id = $1)::boolean AS exists;

-- name: ListDNSCredentials :many
SELECT * FROM dns_provider_credentials WHERE org_id = $1 ORDER BY name;

-- name: UpdateDNSCredential :one
UPDATE dns_provider_credentials SET name = $3, public_cfg = $4, secret_cfg = $5, stored_secret_keys = COALESCE(sqlc.arg(stored_secret_keys)::text[], '{}'), updated_at = now()
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: LockDNSCredential :one
-- Locks the row for the duration of a delete's count-then-delete.
SELECT * FROM dns_provider_credentials WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- name: LockDNSCredentialKeyShare :one
-- FOR KEY SHARE counterpart to LockDNSCredential; see LockCAKeyShare. Not
-- org-scoped: callers that need org ownership check it separately while
-- still holding this lock.
SELECT id FROM dns_provider_credentials WHERE id = $1 FOR KEY SHARE;

-- name: DeleteDNSCredential :execrows
DELETE FROM dns_provider_credentials WHERE id = $1 AND org_id = $2;

-- name: CountDNSCredentialUsers :one
-- Certificates or org defaults whose rules reference the credential.
SELECT (
    (SELECT count(*) FROM certificates c
      WHERE c.verification_rules @> jsonb_build_array(jsonb_build_object('dnsCredentialId', sqlc.arg(id)::uuid::text))
         OR c.overrides->'verificationRules' @> jsonb_build_array(jsonb_build_object('dnsCredentialId', sqlc.arg(id)::uuid::text)))
  + (SELECT count(*) FROM issuance_defaults d
      WHERE d.config->'verificationRules' @> jsonb_build_array(jsonb_build_object('dnsCredentialId', sqlc.arg(id)::uuid::text)))
)::bigint AS users;

-- name: CountDNSCredentialUsersByOrg :many
-- CountDNSCredentialUsers for every credential of the org in one pass over
-- that org's certificates and its issuance defaults (a (referrer, credential)
-- pair counts once, as the OR in the single-credential query does).
WITH refs AS (
    SELECT c.id AS referrer, r->>'dnsCredentialId' AS cred
    FROM certificates c
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(c.verification_rules) = 'array' THEN c.verification_rules ELSE '[]'::jsonb END
        || CASE WHEN jsonb_typeof(c.overrides->'verificationRules') = 'array' THEN c.overrides->'verificationRules' ELSE '[]'::jsonb END
    ) AS r
    WHERE c.org_id = sqlc.arg(org_id)
    UNION
    SELECT d.org_id, r->>'dnsCredentialId'
    FROM issuance_defaults d
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(d.config->'verificationRules') = 'array' THEN d.config->'verificationRules' ELSE '[]'::jsonb END
    ) AS r
    WHERE d.org_id = sqlc.arg(org_id)
)
SELECT dc.id, count(refs.referrer)::bigint AS users
FROM dns_provider_credentials dc
LEFT JOIN refs ON refs.cred = dc.id::text
WHERE dc.org_id = sqlc.arg(org_id)
GROUP BY dc.id;
