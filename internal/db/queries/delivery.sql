-- name: ListLayouts :many
SELECT * FROM output_specs WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetLayout :one
SELECT * FROM output_specs WHERE id = $1 AND org_id = $2;

-- name: CreateLayout :one
INSERT INTO output_specs (org_id, name, files, password, extra_cert_ids) VALUES ($1, $2, $3, $4, $5) RETURNING *;

-- name: UpdateLayout :one
UPDATE output_specs SET name = sqlc.arg(name), files = sqlc.arg(files), password = sqlc.arg(password),
       extra_cert_ids = sqlc.arg(extra_cert_ids), updated_at = now()
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) RETURNING *;

-- name: DeleteLayout :execrows
DELETE FROM output_specs WHERE id = $1 AND org_id = $2;

-- name: LayoutGrantCounts :many
SELECT o.id, count(g.id)::bigint AS grants
FROM output_specs o LEFT JOIN client_cert_grants g ON g.output_spec_id = o.id AND g.removed_at IS NULL
WHERE o.id = ANY(sqlc.arg(ids)::uuid[]) GROUP BY o.id;

-- name: LayoutDependents :many
SELECT c.name AS client_name, ce.name AS certificate_name, (g.removed_at IS NOT NULL)::bool AS removing
FROM client_cert_grants g
JOIN clients c ON c.id = g.client_id
JOIN certificates ce ON ce.id = g.cert_id
JOIN output_specs o ON o.id = g.output_spec_id
WHERE g.output_spec_id = sqlc.arg(id) AND o.org_id = sqlc.arg(org_id)
ORDER BY c.name, ce.name LIMIT 6;

-- name: LockCertsForExtra :many
-- Locks FOR KEY SHARE the candidate extra certificates a layout write
-- references (scoped to the org), so a concurrent certificate delete
-- (api.DeleteCertificate's FOR UPDATE lock) serializes against this layout
-- write instead of racing it into a dangling extra_cert_ids entry. Returns
-- current_version_id so the caller can also check each has one, in the
-- same round trip.
SELECT id, current_version_id FROM certificates
WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND org_id = sqlc.arg(org_id)
FOR KEY SHARE;

-- name: LayoutsListingExtraCert :many
-- Layouts (any org, but callers scope by org_id) that bundle cert_id as an
-- extra certificate; DeleteCertificate 409s naming these instead of
-- deleting a certificate a layout still renders.
SELECT name FROM output_specs
WHERE org_id = sqlc.arg(org_id) AND sqlc.arg(cert_id)::uuid = ANY(extra_cert_ids)
ORDER BY lower(name) LIMIT 6;

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
FROM client_cert_grants g
JOIN clients c ON c.id = g.client_id
JOIN certificates ce ON ce.id = g.cert_id
JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.deploy_target_id = sqlc.arg(id) AND t.org_id = sqlc.arg(org_id)
ORDER BY c.name, ce.name LIMIT 6;

-- name: ListHooks :many
SELECT * FROM hooks WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetHook :one
SELECT * FROM hooks WHERE id = $1 AND org_id = $2;

-- name: LockHook :one
-- Locks the hook row FOR UPDATE before DeleteHook re-checks HookDependents,
-- so a concurrent grant create/update that locks this row FOR SHARE
-- (LockHooksInOrg) either finishes and is seen by the dependents re-check,
-- or blocks behind this delete and later finds the hook gone.
SELECT * FROM hooks WHERE id = $1 AND org_id = $2 FOR UPDATE;

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
WHERE sqlc.arg(hook_id)::uuid = ANY(g.hook_ids)
  AND EXISTS (SELECT 1 FROM hooks h WHERE h.id = sqlc.arg(hook_id)::uuid AND h.org_id = sqlc.arg(org_id))
ORDER BY c.name, ce.name LIMIT 6;
