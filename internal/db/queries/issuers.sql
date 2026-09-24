-- name: CreateCA :one
INSERT INTO cas (org_id, name, preset, directory_url, trust_bundle_pem, eab_kid, eab_hmac, resolvers)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetCA :one
SELECT * FROM cas WHERE id = $1 AND org_id = $2;

-- name: GetCAByID :one
-- Ignores org scope: used only to check that a CA referenced by the global
-- issuance_defaults settings section (which is not org-scoped) still exists.
SELECT * FROM cas WHERE id = $1;

-- name: ListCAs :many
SELECT * FROM cas WHERE org_id = $1 ORDER BY name;

-- name: UpdateCA :one
UPDATE cas SET name = $3, preset = $4, directory_url = $5, trust_bundle_pem = $6,
    eab_kid = $7, eab_hmac = $8, resolvers = $9, updated_at = now()
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: DeleteCA :execrows
DELETE FROM cas WHERE id = $1 AND org_id = $2;

-- name: CountCAUsers :one
SELECT (
    (SELECT count(*) FROM acme_accounts a WHERE a.ca_id = sqlc.arg(id)::uuid)
  + (SELECT count(*) FROM certificates c WHERE c.overrides->>'caId' = sqlc.arg(id)::uuid::text)
  + (SELECT count(*) FROM issuance_defaults d WHERE d.config->>'caId' = sqlc.arg(id)::uuid::text)
)::bigint AS users;

-- name: CreateAccount :one
INSERT INTO acme_accounts (org_id, ca_id, email, account_key, registration_uri)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetAccount :one
SELECT * FROM acme_accounts WHERE id = $1 AND org_id = $2;

-- name: GetAccountByID :one
-- Ignores org scope: used only to check that an account referenced by the
-- global issuance_defaults settings section still exists (and which CA it
-- belongs to).
SELECT * FROM acme_accounts WHERE id = $1;

-- name: ListAccounts :many
SELECT * FROM acme_accounts WHERE org_id = $1 ORDER BY email;

-- name: DeleteAccount :execrows
DELETE FROM acme_accounts WHERE id = $1 AND org_id = $2;

-- name: CountAccountUsers :one
SELECT (
    (SELECT count(*) FROM certificates c WHERE c.overrides->>'accountId' = sqlc.arg(id)::uuid::text)
  + (SELECT count(*) FROM issuance_defaults d WHERE d.config->>'accountId' = sqlc.arg(id)::uuid::text)
)::bigint AS users;
