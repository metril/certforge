-- name: CreateGrant :one
INSERT INTO client_cert_grants (client_id, cert_id, delivery, output_spec_id, deploy_target_id, hook_ids, auto_remediate)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: LockGrant :one
SELECT client_cert_grants.* FROM client_cert_grants
WHERE client_cert_grants.id = $1 AND removed_at IS NULL AND client_id IN (SELECT c.id FROM clients c WHERE c.org_id = $2)
FOR UPDATE;

-- name: UpdateGrant :one
UPDATE client_cert_grants SET delivery = sqlc.arg(delivery), output_spec_id = sqlc.narg(output_spec_id),
       deploy_target_id = sqlc.narg(deploy_target_id), hook_ids = sqlc.arg(hook_ids),
       auto_remediate = sqlc.arg(auto_remediate), updated_at = now()
WHERE id = sqlc.arg(id) RETURNING *;

-- name: MarkGrantRemoved :exec
-- removed_revision is the client's desired_revision after the bump that
-- announces this removal; Report confirms the removal only from a report at
-- or past it.
UPDATE client_cert_grants SET removed_at = now(), removed_revision = sqlc.arg(removed_revision), updated_at = now()
WHERE id = sqlc.arg(id);

-- name: DeleteGrantRow :exec
DELETE FROM client_cert_grants WHERE id = $1;

-- name: GrantViews :many
SELECT g.id, g.client_id, c.name AS client_name, g.cert_id, ce.name AS certificate_name, g.delivery,
       g.output_spec_id, g.deploy_target_id, g.hook_ids, g.auto_remediate, g.created_at, g.updated_at,
       d.state, d.version_id, d.expected, d.installed, d.error, d.reported_at, d.updated_at AS deployment_updated_at
FROM client_cert_grants g
JOIN clients c ON c.id = g.client_id
JOIN certificates ce ON ce.id = g.cert_id
JOIN deployments d ON d.grant_id = g.id
WHERE c.org_id = sqlc.arg(org_id) AND g.removed_at IS NULL
  AND (sqlc.narg(client_id)::uuid IS NULL OR g.client_id = sqlc.narg(client_id)::uuid)
  AND (sqlc.narg(grant_id)::uuid IS NULL OR g.id = sqlc.narg(grant_id)::uuid)
ORDER BY lower(ce.name), g.id;

-- name: CertificateInOrg :one
SELECT EXISTS (SELECT 1 FROM certificates WHERE id = $1 AND org_id = $2)::bool;

-- name: CertificateDeployments :many
SELECT g.id AS grant_id, g.client_id, c.name AS client_name, c.status AS client_status, c.last_seen AS client_last_seen, c.site_id, g.delivery,
       g.output_spec_id AS layout_id, o.name AS layout_name, g.deploy_target_id, t.name AS deploy_target_name,
       d.state, d.version_id, d.expected, d.installed, d.error, d.reported_at, d.updated_at AS deployment_updated_at
FROM client_cert_grants g
JOIN clients c ON c.id = g.client_id
JOIN deployments d ON d.grant_id = g.id
LEFT JOIN output_specs o ON o.id = g.output_spec_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.cert_id = sqlc.arg(cert_id) AND c.org_id = sqlc.arg(org_id) AND g.removed_at IS NULL
ORDER BY lower(c.name), g.id;

-- name: UpsertDeployment :exec
INSERT INTO deployments (grant_id, version_id, state, expected, error, updated_at)
VALUES (sqlc.arg(grant_id), sqlc.narg(version_id), 'pending', sqlc.arg(expected), '', now())
ON CONFLICT (grant_id) DO UPDATE SET version_id = EXCLUDED.version_id, state = 'pending',
       expected = EXCLUDED.expected, error = '', updated_at = now();

-- name: GrantSources :many
SELECT g.id, g.client_id, g.cert_id, g.delivery, ce.name AS certificate_name, ce.current_version_id,
       o.files AS layout_files, t.type AS target_type, t.config AS target_config
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
LEFT JOIN output_specs o ON o.id = g.output_spec_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.id = ANY(sqlc.arg(ids)::uuid[]) AND g.removed_at IS NULL;

-- name: LiveGrantIDsForCert :many
SELECT id FROM client_cert_grants WHERE cert_id = $1 AND removed_at IS NULL;

-- name: LiveGrantIDsUsingLayout :many
SELECT id FROM client_cert_grants WHERE output_spec_id = $1 AND removed_at IS NULL;

-- name: LiveGrantIDsUsingTarget :many
SELECT id FROM client_cert_grants WHERE deploy_target_id = $1 AND removed_at IS NULL;

-- name: LiveGrantIDsUsingHook :many
SELECT id FROM client_cert_grants WHERE sqlc.arg(hook_id)::uuid = ANY(hook_ids) AND removed_at IS NULL;

-- name: CountLiveGrantsByCert :many
SELECT cert_id, count(*)::bigint AS grants FROM client_cert_grants
WHERE cert_id = ANY(sqlc.arg(ids)::uuid[]) AND removed_at IS NULL GROUP BY cert_id;

-- name: CountAllGrantsByCert :many
-- Counts live AND removal-pending grants (any row still present; a
-- removal-pending grant is only deleted once its agent confirms the files
-- are gone), since cert_id is ON DELETE CASCADE and a certificate delete
-- must not silently orphan a grant an agent still has to act on.
SELECT cert_id, count(*)::bigint AS grants FROM client_cert_grants
WHERE cert_id = ANY(sqlc.arg(ids)::uuid[]) GROUP BY cert_id;

-- name: LockCertificateForGrant :one
-- Locks the certificate FOR KEY SHARE before a grant is inserted, so it
-- conflicts with DeleteCertificate's FOR UPDATE lock (LockCertificateForGrant/
-- GetCertificateForUpdate are incompatible row-lock modes) and the two
-- serialize: whichever locks first is seen by the other, so a certificate
-- can never be deleted out from under a grant being created for it. Also
-- conflicts with UpdateCertificate's rename lock (GetCertificateForUpdate,
-- also FOR UPDATE): see checkRefs/CreateGrant's package-level lock-order
-- comment in internal/agents.
SELECT id FROM certificates WHERE id = $1 AND org_id = $2 FOR KEY SHARE;

-- name: LockLayoutForGrant :one
-- Locks the layout FOR SHARE before a grant references it (output_spec_id
-- is a real FK, so the insert/update would otherwise take this lock
-- implicitly, at whatever point the statement runs): FOR SHARE conflicts
-- with UpdateLayout's implicit FOR NO KEY UPDATE row lock, so the two
-- serialize instead of racing. FOR KEY SHARE would not do this: Postgres
-- treats FOR KEY SHARE and FOR NO KEY UPDATE as compatible with each other,
-- so that pair never actually blocked one another, and a layout PATCH
-- racing a CreateGrant referencing the same layout could each proceed
-- without seeing the other, leaving the grant rendered from a pre-update
-- layout that the PATCH's own Resync had already read past. See the
-- package-level lock-order comment in internal/agents.
SELECT id FROM output_specs WHERE id = $1 AND org_id = $2 FOR SHARE;

-- name: LockTargetForGrant :one
-- Locks the deploy target FOR SHARE before a grant references it, for the
-- same reason as LockLayoutForGrant.
SELECT id FROM deploy_targets WHERE id = $1 AND org_id = $2 FOR SHARE;

-- name: GrantClientIDs :many
-- Cheap grant id -> client id lookup (no joins), used to isolate a
-- multi-client re-render (OnVersion, SweepDeployments) into one
-- transaction per client, so a render failure for one client's grant
-- cannot roll back or stall another client's already-computed update.
SELECT id, client_id FROM client_cert_grants WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND removed_at IS NULL;

-- name: BumpClientRevisions :many
UPDATE clients SET desired_revision = desired_revision + 1
WHERE id = ANY(sqlc.arg(ids)::uuid[]) RETURNING id, desired_revision;

-- name: ClientGrantPaths :many
SELECT g.id, g.client_id, g.removed_at, ce.name AS certificate_name, o.files AS layout_files,
       t.type AS target_type, t.config AS target_config, d.expected
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
LEFT JOIN deployments d ON d.grant_id = g.id
LEFT JOIN output_specs o ON o.id = g.output_spec_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.client_id = ANY(sqlc.arg(client_ids)::uuid[])
ORDER BY g.created_at, g.id;

-- name: StaleDeploymentGrantIDs :many
SELECT g.id FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
JOIN deployments d ON d.grant_id = g.id
WHERE g.removed_at IS NULL AND ce.current_version_id IS NOT NULL
  AND d.version_id IS DISTINCT FROM ce.current_version_id;

-- name: LockHooksInOrg :many
-- Locks the org's hooks referenced by ids FOR SHARE, so a concurrent
-- DeleteHook (which locks the hook row FOR UPDATE before deleting) either
-- blocks until this transaction commits and then sees the new grant among
-- its dependents, or has already committed the delete and this transaction
-- sees fewer rows than ids, and the caller rejects the grant. hook_ids has
-- no FK (it is a plain array), so this lock is what keeps a hook id from
-- going dangling.
SELECT id FROM hooks WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND org_id = sqlc.arg(org_id) FOR SHARE;

-- name: CheckGrantRefs :one
SELECT
  EXISTS (SELECT 1 FROM certificates WHERE certificates.id = sqlc.arg(cert_id) AND certificates.org_id = sqlc.arg(org_id))::bool AS cert_ok,
  (sqlc.narg(layout_id)::uuid IS NULL OR EXISTS (SELECT 1 FROM output_specs WHERE output_specs.id = sqlc.narg(layout_id)::uuid AND output_specs.org_id = sqlc.arg(org_id)))::bool AS layout_ok,
  (sqlc.narg(target_id)::uuid IS NULL OR EXISTS (SELECT 1 FROM deploy_targets WHERE deploy_targets.id = sqlc.narg(target_id)::uuid AND deploy_targets.org_id = sqlc.arg(org_id)))::bool AS target_ok,
  (SELECT count(*) FROM hooks WHERE hooks.id = ANY(sqlc.arg(hook_ids)::uuid[]) AND hooks.org_id = sqlc.arg(org_id))::bigint AS hooks_found;
