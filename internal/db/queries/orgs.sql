-- name: CreateOrg :one
INSERT INTO orgs (slug, name) VALUES ($1, $2) RETURNING *;

-- name: ListOrgs :many
SELECT * FROM orgs ORDER BY name, slug;

-- name: GetOrgBySlug :one
SELECT * FROM orgs WHERE slug = $1;
