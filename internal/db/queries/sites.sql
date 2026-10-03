-- name: ListSites :many
SELECT * FROM sites WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetSite :one
SELECT * FROM sites WHERE id = $1 AND org_id = $2;

-- name: CreateSite :one
INSERT INTO sites (org_id, name) VALUES ($1, $2) RETURNING *;

-- name: UpdateSiteName :one
UPDATE sites SET name = sqlc.arg(name) WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) RETURNING *;

-- name: DeleteSite :execrows
DELETE FROM sites WHERE id = $1 AND org_id = $2;

-- name: CountSiteClients :one
SELECT count(*) FROM clients WHERE site_id = $1 AND org_id = $2;
