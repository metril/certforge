-- name: CreateDNSCredential :one
INSERT INTO dns_provider_credentials (org_id, name, provider_code, public_cfg, secret_cfg)
VALUES ($1, $2, $3, $4, $5)
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
UPDATE dns_provider_credentials SET name = $3, public_cfg = $4, secret_cfg = $5, updated_at = now()
WHERE id = $1 AND org_id = $2
RETURNING *;

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
