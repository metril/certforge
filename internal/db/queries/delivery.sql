-- name: ListLayouts :many
SELECT * FROM output_specs WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetLayout :one
SELECT * FROM output_specs WHERE id = $1 AND org_id = $2;

-- name: CreateLayout :one
INSERT INTO output_specs (org_id, name, files) VALUES ($1, $2, $3) RETURNING *;

-- name: UpdateLayout :one
UPDATE output_specs SET name = sqlc.arg(name), files = sqlc.arg(files), updated_at = now()
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) RETURNING *;

-- name: DeleteLayout :execrows
DELETE FROM output_specs WHERE id = $1 AND org_id = $2;

-- name: LayoutGrantCounts :many
SELECT o.id, count(g.id)::bigint AS grants
FROM output_specs o LEFT JOIN client_cert_grants g ON g.output_spec_id = o.id AND g.removed_at IS NULL
WHERE o.id = ANY(sqlc.arg(ids)::uuid[]) GROUP BY o.id;

-- name: LayoutDependents :many
SELECT c.name AS client_name, ce.name AS certificate_name, (g.removed_at IS NOT NULL)::bool AS removing
FROM client_cert_grants g JOIN clients c ON c.id = g.client_id JOIN certificates ce ON ce.id = g.cert_id
WHERE g.output_spec_id = $1 ORDER BY c.name, ce.name LIMIT 6;

-- name: ListDeployTargets :many
SELECT * FROM deploy_targets WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetDeployTarget :one
SELECT * FROM deploy_targets WHERE id = $1 AND org_id = $2;

-- name: CreateDeployTarget :one
INSERT INTO deploy_targets (org_id, name, type, config) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: UpdateDeployTarget :one
UPDATE deploy_targets SET name = sqlc.arg(name), config = sqlc.arg(config), updated_at = now()
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) RETURNING *;

-- name: DeleteDeployTarget :execrows
DELETE FROM deploy_targets WHERE id = $1 AND org_id = $2;

-- name: DeployTargetGrantCounts :many
SELECT t.id, count(g.id)::bigint AS grants
FROM deploy_targets t LEFT JOIN client_cert_grants g ON g.deploy_target_id = t.id AND g.removed_at IS NULL
WHERE t.id = ANY(sqlc.arg(ids)::uuid[]) GROUP BY t.id;

-- name: DeployTargetDependents :many
SELECT c.name AS client_name, ce.name AS certificate_name, (g.removed_at IS NOT NULL)::bool AS removing
FROM client_cert_grants g JOIN clients c ON c.id = g.client_id JOIN certificates ce ON ce.id = g.cert_id
WHERE g.deploy_target_id = $1 ORDER BY c.name, ce.name LIMIT 6;

-- name: ListHooks :many
SELECT * FROM hooks WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetHook :one
SELECT * FROM hooks WHERE id = $1 AND org_id = $2;

-- name: CreateHook :one
INSERT INTO hooks (org_id, name, phase, argv, timeout_seconds) VALUES ($1, $2, $3, $4, $5) RETURNING *;

-- name: UpdateHook :one
UPDATE hooks SET name = sqlc.arg(name), phase = sqlc.arg(phase), argv = sqlc.arg(argv),
       timeout_seconds = sqlc.arg(timeout_seconds), updated_at = now()
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) RETURNING *;

-- name: DeleteHook :execrows
DELETE FROM hooks WHERE id = $1 AND org_id = $2;

-- name: HookGrantCounts :many
SELECT h.id, count(g.id)::bigint AS grants
FROM hooks h LEFT JOIN client_cert_grants g ON h.id = ANY(g.hook_ids) AND g.removed_at IS NULL
WHERE h.id = ANY(sqlc.arg(ids)::uuid[]) GROUP BY h.id;

-- name: HookDependents :many
SELECT c.name AS client_name, ce.name AS certificate_name, (g.removed_at IS NOT NULL)::bool AS removing
FROM client_cert_grants g JOIN clients c ON c.id = g.client_id JOIN certificates ce ON ce.id = g.cert_id
WHERE sqlc.arg(hook_id)::uuid = ANY(g.hook_ids) ORDER BY c.name, ce.name LIMIT 6;
