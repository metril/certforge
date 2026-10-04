-- name: CreateCA :one
INSERT INTO cas (org_id, name, type, config, secret_cfg, not_before, not_after, preset, directory_url, trust_bundle_pem, eab_kid, eab_hmac, resolvers)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
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
UPDATE cas SET name = $3, type = $4, config = $5, preset = $6, directory_url = $7, trust_bundle_pem = $8,
    eab_kid = $9, eab_hmac = $10, resolvers = $11, updated_at = now()
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: UpdateCACrypto :one
-- Rotate and Revoke each update only the crypto-bearing columns (config,
-- secret_cfg, not_before, not_after, crl_number), leaving name/preset/eab/
-- resolvers untouched; the caller has already locked the row FOR UPDATE
-- (LockCA), inside the same transaction as this write.
UPDATE cas SET config = $3, secret_cfg = $4, not_before = $5, not_after = $6, crl_number = $7, updated_at = now()
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: LockCA :one
-- Locks the row for the duration of a delete's count-then-delete, so a
-- concurrent insert that references this CA (acme_accounts.ca_id has an FK
-- to cas.id) blocks until the delete's transaction commits or rolls back.
SELECT * FROM cas WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- name: LockCAKeyShare :one
-- Takes a FOR KEY SHARE lock on the CA row: a weaker lock than LockCA's FOR
-- UPDATE that still conflicts with it, so writers that store a caId
-- reference in jsonb (org and global issuance defaults) can hold this while
-- they validate and write, and a concurrent DeleteCA blocks until they
-- finish instead of racing past them. Not org-scoped: callers that need org
-- ownership check it separately while still holding this lock.
SELECT id FROM cas WHERE id = $1 FOR KEY SHARE;

-- name: DeleteCA :execrows
DELETE FROM cas WHERE id = $1 AND org_id = $2;

-- name: CountCAUsers :one
SELECT (
    (SELECT count(*) FROM acme_accounts a WHERE a.ca_id = sqlc.arg(id)::uuid)
  + (SELECT count(*) FROM certificates c WHERE c.overrides->>'caId' = sqlc.arg(id)::uuid::text)
  + (SELECT count(*) FROM issuance_defaults d WHERE d.config->>'caId' = sqlc.arg(id)::uuid::text)
)::bigint AS users;

-- name: CountCAIssuedLive :one
-- Issued versions of a CA that are neither expired nor revoked; deleting the
-- CA would orphan them (ca_id set NULL) and make them unrevocable.
SELECT count(*)::bigint FROM certificate_versions
WHERE ca_id = $1 AND revoked_at IS NULL AND not_after > now();

-- name: CreateAccount :one
INSERT INTO acme_accounts (org_id, ca_id, email, account_key, registration_uri)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: AccountExistsByEmail :one
SELECT EXISTS (SELECT 1 FROM acme_accounts WHERE ca_id = $1 AND email = $2);

-- name: GetAccount :one
SELECT * FROM acme_accounts WHERE id = $1 AND org_id = $2;

-- name: GetAccountByID :one
-- Ignores org scope: used only to check that an account referenced by the
-- global issuance_defaults settings section still exists (and which CA it
-- belongs to).
SELECT * FROM acme_accounts WHERE id = $1;

-- name: ListAccounts :many
SELECT * FROM acme_accounts WHERE org_id = $1 ORDER BY email;

-- name: LockAccount :one
-- Locks the row for the duration of a delete's count-then-delete.
SELECT * FROM acme_accounts WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- name: LockAccountKeyShare :one
-- FOR KEY SHARE counterpart to LockAccount; see LockCAKeyShare.
SELECT id FROM acme_accounts WHERE id = $1 FOR KEY SHARE;

-- name: DeleteAccount :execrows
DELETE FROM acme_accounts WHERE id = $1 AND org_id = $2;

-- name: CountAccountUsers :one
SELECT (
    (SELECT count(*) FROM certificates c WHERE c.overrides->>'accountId' = sqlc.arg(id)::uuid::text)
  + (SELECT count(*) FROM issuance_defaults d WHERE d.config->>'accountId' = sqlc.arg(id)::uuid::text)
)::bigint AS users;
