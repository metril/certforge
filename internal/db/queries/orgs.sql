-- name: CreateOrg :one
INSERT INTO orgs (slug, name) VALUES ($1, $2) RETURNING *;

-- name: ListOrgs :many
SELECT * FROM orgs ORDER BY name, slug;

-- name: GetOrgBySlug :one
SELECT * FROM orgs WHERE slug = $1;

-- name: GetOrg :one
SELECT * FROM orgs WHERE id = $1;

-- name: UpdateOrgName :one
UPDATE orgs SET name = sqlc.arg(name) WHERE id = sqlc.arg(id) RETURNING *;

-- name: LockOrg :one
SELECT id FROM orgs WHERE id = $1 FOR UPDATE;

-- name: CountOrgDependents :one
SELECT
  (SELECT count(*) FROM certificates c WHERE c.org_id = sqlc.arg(org_id)) AS certificates,
  (SELECT count(*) FROM dns_provider_credentials d WHERE d.org_id = sqlc.arg(org_id)) AS dns_credentials,
  (SELECT count(*) FROM acme_accounts a WHERE a.org_id = sqlc.arg(org_id)) AS acme_accounts,
  (SELECT count(*) FROM cas WHERE cas.org_id = sqlc.arg(org_id)) AS cas,
  (SELECT count(*) FROM role_bindings rb WHERE rb.org_id = sqlc.arg(org_id)) AS role_bindings,
  (SELECT count(*) FROM api_keys k WHERE k.org_id = sqlc.arg(org_id) AND k.revoked_at IS NULL) AS api_keys;

-- name: DeleteOrg :exec
DELETE FROM orgs WHERE id = $1;
