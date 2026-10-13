-- name: ListLayouts :many
SELECT * FROM output_specs WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetLayout :one
SELECT * FROM output_specs WHERE id = $1 AND org_id = $2;

-- name: LockLayout :one
-- Final review finding 1: UpdateLayout reads the row FOR UPDATE (not plain
-- GetLayout) before deciding whether to keep the stored password
-- unchanged, so a concurrent rewrap's CAS on this same row's password
-- column (internal/kek/rewrap.go) cannot commit between this read and
-- UpdateLayout's own write — which would otherwise write the stale,
-- pre-rewrap blob back over it, losing the rewrap
-- (TestRewrapCASLosesRaceSafely). UpdateLayout already runs in its own
-- transaction, so this is the same row, only a stronger lock.
SELECT * FROM output_specs WHERE id = $1 AND org_id = $2 FOR UPDATE;

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

-- name: LayoutKeylessGrantCertificate :one
-- The name of one certificate (the first, by name) with a live grant on
-- this layout whose current version has no stored key. Used by
-- UpdateLayout (R10 mirror, 4A final review finding 1): an update that
-- makes the layout need a key (delivery.NeedsKey on the new files) must be
-- refused with 422 when any of its live grants' certificates would then
-- have nothing to render a key from, rather than storing the update and
-- only discovering ErrNoKey later, opaquely, from the Resync render.
-- pgx.ErrNoRows means none found (nothing to refuse).
SELECT ce.name FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
JOIN certificate_versions v ON v.id = ce.current_version_id
WHERE g.output_spec_id = sqlc.arg(id) AND g.removed_at IS NULL AND v.private_key IS NULL
ORDER BY ce.name LIMIT 1;

-- name: LayoutDependents :many
-- Final review finding 2: client_id is LEFT JOINed (a server grant has
-- none) so a layout used only by server grants still lists its dependents
-- instead of silently reporting none; client_name names the deploy target
-- for a server grant (there is no client to name).
SELECT COALESCE(c.name, t.name) AS client_name, ce.name AS certificate_name, (g.removed_at IS NOT NULL)::bool AS removing
FROM client_cert_grants g
LEFT JOIN clients c ON c.id = g.client_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
JOIN certificates ce ON ce.id = g.cert_id
JOIN output_specs o ON o.id = g.output_spec_id
WHERE g.output_spec_id = sqlc.arg(id) AND o.org_id = sqlc.arg(org_id)
ORDER BY COALESCE(c.name, t.name), ce.name LIMIT 6;

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
WHERE org_id = sqlc.arg(org_id) AND extra_cert_ids @> ARRAY[sqlc.arg(cert_id)::uuid]
ORDER BY lower(name) LIMIT 6;

-- name: ListDeployTargets :many
SELECT * FROM deploy_targets WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetDeployTarget :one
SELECT * FROM deploy_targets WHERE id = $1 AND org_id = $2;

-- name: DeployTargetForUpdate :one
-- Phase 7A Task 1: read+lock a target row FOR UPDATE ahead of an update
-- that decides whether to keep stored secrets unchanged (the same
-- LockLayout convention: internal/kek/rewrap.go's concurrent CAS on
-- secret_cfg cannot land between this read and the later write and be
-- silently clobbered by a stale, pre-rewrap blob).
SELECT * FROM deploy_targets WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- name: CreateDeployTarget :one
INSERT INTO deploy_targets (org_id, name, type, runs_on, config, secret_cfg, stored_secret_keys, credential_id)
VALUES ($1, $2, $3, $4, $5, $6, COALESCE(sqlc.arg(stored_secret_keys)::text[], '{}'), sqlc.narg(credential_id)) RETURNING *;

-- name: UpdateDeployTarget :one
UPDATE deploy_targets SET name = sqlc.arg(name), config = sqlc.arg(config), secret_cfg = sqlc.arg(secret_cfg),
       stored_secret_keys = COALESCE(sqlc.arg(stored_secret_keys)::text[], '{}'), credential_id = sqlc.narg(credential_id), updated_at = now()
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) RETURNING *;

-- name: DeleteDeployTarget :execrows
DELETE FROM deploy_targets WHERE id = $1 AND org_id = $2;

-- name: TargetKeylessGrantCertificate :one
-- UpdateDeployTarget's own version of LayoutKeylessGrantCertificate (final
-- review finding 3): the name of one certificate (first, by name) with a
-- live server grant on this target whose current version has no stored
-- key. Used when an update turns includeKey on, so the update is refused
-- (422) before storing a config that would make the next deploy fail with
-- no key to render, instead of discovering it opaquely at deploy time.
-- client_id IS NULL: a server grant only (see LiveGrantIDsForCert's own
-- comment on this filter) — an agent-run target has no includeKey at all.
-- pgx.ErrNoRows means none found (nothing to refuse).
SELECT ce.name FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
JOIN certificate_versions v ON v.id = ce.current_version_id
WHERE g.deploy_target_id = sqlc.arg(id) AND g.removed_at IS NULL AND g.client_id IS NULL AND v.private_key IS NULL
ORDER BY ce.name LIMIT 1;

-- name: DeployTargetGrantCounts :many
SELECT t.id, count(g.id)::bigint AS grants
FROM deploy_targets t LEFT JOIN client_cert_grants g ON g.deploy_target_id = t.id AND g.removed_at IS NULL
WHERE t.id = ANY(sqlc.arg(ids)::uuid[]) GROUP BY t.id;

-- name: DeployTargetDependents :many
-- Final review finding 2: client_id is LEFT JOINed (a server grant has
-- none) so a target used only by server grants still lists its dependents;
-- client_name names the target itself for a server grant (there is no
-- client to name — the target is the very thing being deleted).
SELECT COALESCE(c.name, t.name) AS client_name, ce.name AS certificate_name, (g.removed_at IS NOT NULL)::bool AS removing
FROM client_cert_grants g
LEFT JOIN clients c ON c.id = g.client_id
JOIN certificates ce ON ce.id = g.cert_id
JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.deploy_target_id = sqlc.arg(id) AND t.org_id = sqlc.arg(org_id)
ORDER BY COALESCE(c.name, t.name), ce.name LIMIT 6;

-- name: ListActions :many
SELECT * FROM actions WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetAction :one
SELECT * FROM actions WHERE id = $1 AND org_id = $2;

-- name: LockAction :one
-- Locks the action row FOR UPDATE before DeleteAction re-checks
-- ActionDependents, so a concurrent grant or group create/update that locks
-- this row FOR SHARE (LockActionsInOrg) either finishes and is seen by the
-- dependents re-check, or blocks behind this delete and later finds the
-- action gone.
SELECT * FROM actions WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- name: CreateAction :one
INSERT INTO actions (org_id, name, kind, phase, config, secret_cfg, timeout_seconds, optional)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *;

-- name: UpdateAction :one
UPDATE actions SET name = sqlc.arg(name), kind = sqlc.arg(kind), phase = sqlc.arg(phase), config = sqlc.arg(config),
       secret_cfg = sqlc.arg(secret_cfg), timeout_seconds = sqlc.arg(timeout_seconds), optional = sqlc.arg(optional), updated_at = now()
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) RETURNING *;

-- name: DeleteAction :execrows
DELETE FROM actions WHERE id = $1 AND org_id = $2;

-- name: ActionGrantCounts :many
SELECT a.id, count(g.id)::bigint AS grants
FROM actions a LEFT JOIN client_cert_grants g ON g.steps @> jsonb_build_array(jsonb_build_object('action', a.id)) AND g.removed_at IS NULL
WHERE a.id = ANY(sqlc.arg(ids)::uuid[]) GROUP BY a.id;

-- name: ActionDependents :many
-- Up to 6 live or removal-pending grants (by client, or by target for a
-- server grant) and groups that reference the action.
SELECT (COALESCE(c.name, t.name))::text AS owner_name, ce.name AS certificate_name, 'grant'::text AS dependent_kind,
       (g.removed_at IS NOT NULL)::bool AS removing
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
LEFT JOIN clients c ON c.id = g.client_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.steps @> jsonb_build_array(jsonb_build_object('action', sqlc.arg(action_id)::uuid))
  AND EXISTS (SELECT 1 FROM actions a WHERE a.id = sqlc.arg(action_id)::uuid AND a.org_id = sqlc.arg(org_id))
UNION ALL
SELECT ag.name, ''::text, 'group'::text, false
FROM action_groups ag
WHERE ag.action_ids @> ARRAY[sqlc.arg(action_id)::uuid] AND ag.org_id = sqlc.arg(org_id)
ORDER BY 3, 1, 2 LIMIT 6;

-- name: ListActionGroups :many
SELECT * FROM action_groups WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetActionGroup :one
SELECT * FROM action_groups WHERE id = $1 AND org_id = $2;

-- name: LockActionGroup :one
-- Locks the group row FOR UPDATE before DeleteActionGroup re-checks
-- ActionGroupDependents (see LockAction).
SELECT * FROM action_groups WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- name: CreateActionGroup :one
INSERT INTO action_groups (org_id, name, action_ids) VALUES ($1, $2, $3) RETURNING *;

-- name: UpdateActionGroup :one
UPDATE action_groups SET name = sqlc.arg(name), action_ids = sqlc.arg(action_ids), updated_at = now()
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id) RETURNING *;

-- name: DeleteActionGroup :execrows
DELETE FROM action_groups WHERE id = $1 AND org_id = $2;

-- name: ActionGroupGrantCounts :many
SELECT ag.id, count(g.id)::bigint AS grants
FROM action_groups ag LEFT JOIN client_cert_grants g ON g.steps @> jsonb_build_array(jsonb_build_object('group', ag.id)) AND g.removed_at IS NULL
WHERE ag.id = ANY(sqlc.arg(ids)::uuid[]) GROUP BY ag.id;

-- name: ActionGroupDependents :many
SELECT (COALESCE(c.name, t.name))::text AS owner_name, ce.name AS certificate_name, (g.removed_at IS NOT NULL)::bool AS removing
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
LEFT JOIN clients c ON c.id = g.client_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.steps @> jsonb_build_array(jsonb_build_object('group', sqlc.arg(group_id)::uuid))
  AND EXISTS (SELECT 1 FROM action_groups ag WHERE ag.id = sqlc.arg(group_id)::uuid AND ag.org_id = sqlc.arg(org_id))
ORDER BY 1, 2 LIMIT 6;
