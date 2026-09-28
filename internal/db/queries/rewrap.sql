-- Task 5 (multi-wrapper envelope, rewrap job): one keyset page and one
-- compare-and-swap update per sealed column, for every table RewrapWorker
-- walks (internal/kek.Tables). Paging is by primary key ascending; sqlc.narg
-- lets the first page pass NULL for "after" instead of a sentinel value.
-- Every :execrows update is a CAS (WHERE pk = $1 AND col = $2, the value
-- just read): 0 rows affected means another writer already changed that
-- column since the page was read, and RewrapWorker counts that as
-- remaining rather than overwriting a blob it never decrypted.

-- name: RewrapSettingsPage :many
SELECT key, secret FROM settings
WHERE secret IS NOT NULL AND (sqlc.narg(after)::text IS NULL OR key > sqlc.narg(after))
ORDER BY key LIMIT $1;

-- name: RewrapSettingsGet :one
SELECT key, secret FROM settings WHERE key = $1;

-- name: RewrapSettingsSecretCAS :execrows
UPDATE settings SET secret = $2 WHERE key = $1 AND secret = $3;

-- name: RewrapCasPage :many
SELECT id, eab_hmac, secret_cfg FROM cas
WHERE (eab_hmac IS NOT NULL OR secret_cfg IS NOT NULL)
  AND (sqlc.narg(after)::uuid IS NULL OR id > sqlc.narg(after))
ORDER BY id LIMIT $1;

-- name: RewrapCasEabHmacCAS :execrows
UPDATE cas SET eab_hmac = $2 WHERE id = $1 AND eab_hmac = $3;

-- name: RewrapCasSecretCfgCAS :execrows
UPDATE cas SET secret_cfg = $2 WHERE id = $1 AND secret_cfg = $3;

-- name: RewrapAcmeAccountsPage :many
SELECT id, account_key FROM acme_accounts
WHERE sqlc.narg(after)::uuid IS NULL OR id > sqlc.narg(after)
ORDER BY id LIMIT $1;

-- name: RewrapAcmeAccountsKeyCAS :execrows
UPDATE acme_accounts SET account_key = $2 WHERE id = $1 AND account_key = $3;

-- name: RewrapDnsProviderCredentialsPage :many
SELECT id, secret_cfg FROM dns_provider_credentials
WHERE sqlc.narg(after)::uuid IS NULL OR id > sqlc.narg(after)
ORDER BY id LIMIT $1;

-- name: RewrapDnsProviderCredentialsSecretCAS :execrows
UPDATE dns_provider_credentials SET secret_cfg = $2 WHERE id = $1 AND secret_cfg = $3;

-- name: RewrapOutputSpecsPage :many
SELECT id, password FROM output_specs
WHERE password IS NOT NULL AND (sqlc.narg(after)::uuid IS NULL OR id > sqlc.narg(after))
ORDER BY id LIMIT $1;

-- name: RewrapOutputSpecsPasswordCAS :execrows
UPDATE output_specs SET password = $2 WHERE id = $1 AND password = $3;

-- name: RewrapAgentCasPage :many
SELECT id, key FROM agent_cas
WHERE sqlc.narg(after)::uuid IS NULL OR id > sqlc.narg(after)
ORDER BY id LIMIT $1;

-- name: RewrapAgentCasKeyCAS :execrows
UPDATE agent_cas SET key = $2 WHERE id = $1 AND key = $3;

-- name: RewrapCertificateVersionsPage :many
SELECT id, private_key FROM certificate_versions
WHERE private_key IS NOT NULL AND (sqlc.narg(after)::uuid IS NULL OR id > sqlc.narg(after))
ORDER BY id LIMIT $1;

-- name: RewrapCertificateVersionsKeyCAS :execrows
UPDATE certificate_versions SET private_key = $2 WHERE id = $1 AND private_key = $3;
