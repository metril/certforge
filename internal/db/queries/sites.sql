-- name: ListSitesWithClientCount :many
SELECT s.id, s.org_id, s.name, s.created_at, count(c.id) AS client_count
FROM sites s LEFT JOIN clients c ON c.site_id = s.id AND c.org_id = s.org_id
WHERE s.org_id = $1
GROUP BY s.id
ORDER BY lower(s.name), s.id;

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
