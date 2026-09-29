-- name: CreateGrant :one
INSERT INTO client_cert_grants (client_id, cert_id, delivery, output_spec_id, deploy_target_id, hook_ids, auto_remediate)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: LockGrant :one
SELECT client_cert_grants.* FROM client_cert_grants
WHERE client_cert_grants.id = $1 AND removed_at IS NULL AND client_id IN (SELECT c.id FROM clients c WHERE c.org_id = $2)
FOR UPDATE;

-- name: LockGrantAny :one
-- Like LockGrant but without the removed_at IS NULL filter: DeleteGrant
-- uses this so a force delete (or a plain delete's own lookup) can reach a
-- grant that is already removal-pending, not only a still-live one.
SELECT client_cert_grants.* FROM client_cert_grants
WHERE client_cert_grants.id = $1 AND client_id IN (SELECT c.id FROM clients c WHERE c.org_id = $2)
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

-- name: RemovalPendingGrantsForClient :many
-- Revoking a client can never be confirmed by its agent again, so
-- RevokeClient hard-deletes every grant of this client still awaiting
-- removal instead of leaving it removal-pending forever.
SELECT * FROM client_cert_grants WHERE client_id = $1 AND removed_at IS NOT NULL FOR UPDATE;

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
INSERT INTO deployments (grant_id, version_id, state, expected, error, extra_version_ids, updated_at)
VALUES (sqlc.arg(grant_id), sqlc.narg(version_id), 'pending', sqlc.arg(expected), '', sqlc.arg(extra_version_ids)::uuid[], now())
ON CONFLICT (grant_id) DO UPDATE SET version_id = EXCLUDED.version_id, state = 'pending',
       expected = EXCLUDED.expected, error = '', extra_version_ids = EXCLUDED.extra_version_ids, updated_at = now();

-- name: GrantSources :many
SELECT g.id, g.client_id, g.cert_id, g.delivery, ce.name AS certificate_name,
       ce.common_name AS certificate_common_name, ce.sans AS certificate_sans, ce.current_version_id,
       o.files AS layout_files, o.password AS layout_password, o.extra_cert_ids AS layout_extra_cert_ids,
       t.type AS target_type, t.config AS target_config
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
LEFT JOIN output_specs o ON o.id = g.output_spec_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.id = ANY(sqlc.arg(ids)::uuid[]) AND g.removed_at IS NULL;

-- name: LiveGrantIDsForCert :many
-- client_id IS NOT NULL: a server grant (Task 11) is deployed by
-- internal/deploy.Dispatcher, its own issuance.VersionListener, never by
-- agents.Service.render/OnVersion (clientOf's doc comment).
SELECT id FROM client_cert_grants WHERE cert_id = $1 AND removed_at IS NULL AND client_id IS NOT NULL;

-- name: LiveGrantIDsForExtraCert :many
-- Live grants whose layout bundles cert_id as an extra certificate: a new
-- version of an extra certificate must re-render these grants too, not
-- only the grants of cert_id's own certificate. client_id IS NOT NULL: see
-- LiveGrantIDsForCert.
SELECT g.id FROM client_cert_grants g
JOIN output_specs o ON o.id = g.output_spec_id
WHERE g.removed_at IS NULL AND g.client_id IS NOT NULL AND sqlc.arg(cert_id)::uuid = ANY(o.extra_cert_ids);

-- name: LiveGrantIDsUsingLayout :many
-- client_id IS NOT NULL: see LiveGrantIDsForCert.
SELECT id FROM client_cert_grants WHERE output_spec_id = $1 AND removed_at IS NULL AND client_id IS NOT NULL;

-- name: LiveGrantIDsUsingTarget :many
-- client_id IS NOT NULL: a server grant's deploy_target_id names the
-- server-run target itself (not an agent-side Traefik target), and its
-- redeploy path never goes through agents.Resync; see LiveGrantIDsForCert.
SELECT id FROM client_cert_grants WHERE deploy_target_id = $1 AND removed_at IS NULL AND client_id IS NOT NULL;

-- name: LiveGrantIDsUsingHook :many
-- client_id IS NOT NULL: see LiveGrantIDsForCert (a server grant never has
-- hooks today, but this keeps the invariant explicit).
SELECT id FROM client_cert_grants WHERE sqlc.arg(hook_id)::uuid = ANY(hook_ids) AND removed_at IS NULL AND client_id IS NOT NULL;

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
-- package-level lock-order comment in internal/agents. files rides along so
-- checkRefs's keyless-grant rule (delivery.NeedsKey) needs no second
-- round trip to the same now-locked row.
SELECT id, files FROM output_specs WHERE id = $1 AND org_id = $2 FOR SHARE;

-- name: CertificateCurrentHasKey :one
-- Reports whether cert_id's current version (if any) has a stored key, for
-- the keyless-grant rule (createGrant/updateGrant, R10): a layout that
-- needs a key, or any deploy target (Traefik always renders fullchain +
-- key), cannot be granted against a keyless current version. has_version
-- is false only when the certificate has no current version yet (C3:
-- nothing to check against yet, so nothing is refused).
SELECT (c.current_version_id IS NOT NULL)::bool AS has_version,
       COALESCE(v.private_key IS NOT NULL, false)::bool AS has_key
FROM certificates c
LEFT JOIN certificate_versions v ON v.id = c.current_version_id
WHERE c.id = sqlc.arg(cert_id)::uuid;

-- name: LockTargetForGrant :one
-- Locks the deploy target FOR SHARE before a grant references it, for the
-- same reason as LockLayoutForGrant. runs_on rides along so checkRefs can
-- refuse a client grant (createGrant/updateGrant) referencing a
-- server-run target (Task 11 pre-flight ruling: a client on a server
-- target is a 422, the mirror of createServerGrant's own agent-target
-- check) without a second round trip to the same now-locked row.
SELECT id, runs_on FROM deploy_targets WHERE id = $1 AND org_id = $2 FOR SHARE;

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
-- A deployment is stale when its own version_id lags the certificate's
-- current_version_id, or (for a grant with a layout that bundles extra
-- certificates) when extra_version_ids no longer matches the extra
-- certificates' own current_version_id, in the layout's extra_cert_ids
-- order: a new version of an extra certificate makes this grant stale too,
-- covering an OnVersion call the extra certificate's own render skipped.
SELECT g.id FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
JOIN deployments d ON d.grant_id = g.id
LEFT JOIN output_specs o ON o.id = g.output_spec_id
WHERE g.removed_at IS NULL AND g.client_id IS NOT NULL AND ce.current_version_id IS NOT NULL
  AND (d.version_id IS DISTINCT FROM ce.current_version_id
       OR d.extra_version_ids IS DISTINCT FROM (
            SELECT COALESCE(array_agg(ec.current_version_id ORDER BY x.ord), '{}'::uuid[])
            FROM unnest(COALESCE(o.extra_cert_ids, '{}'::uuid[])) WITH ORDINALITY AS x(id, ord)
            JOIN certificates ec ON ec.id = x.id
          ));

-- name: LockHooksInOrg :many
-- Locks the org's hooks referenced by ids FOR SHARE, so a concurrent
-- DeleteHook (which locks the hook row FOR UPDATE before deleting) either
-- blocks until this transaction commits and then sees the new grant among
-- its dependents, or has already committed the delete and this transaction
-- sees fewer rows than ids, and the caller rejects the grant. hook_ids has
-- no FK (it is a plain array), so this lock is what keeps a hook id from
-- going dangling.
SELECT id FROM hooks WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND org_id = sqlc.arg(org_id) FOR SHARE;

-- ---- server grants (Task 11: client-less grants on a server-run deploy
-- target). Every query below scopes by deploy_targets.org_id through the
-- target join (pre-flight ruling), the way the queries above scope by
-- clients.org_id.

-- name: LockServerTarget :one
-- Locks the deploy target FOR SHARE, org-scoped, before a server grant
-- references it (same reason as LockTargetForGrant); the caller checks
-- runs_on = 'server' itself (an agent-run target is a 422, not a 404).
SELECT * FROM deploy_targets WHERE id = $1 AND org_id = $2 FOR SHARE;

-- name: CreateServerGrant :one
-- client_id is NULL, delivery is always 'push' (there is no agent pull
-- schedule for a server grant), hook_ids is empty (hooks are agent-side).
INSERT INTO client_cert_grants (client_id, cert_id, delivery, output_spec_id, deploy_target_id, hook_ids, auto_remediate)
VALUES (NULL, $1, 'push', $2, $3, '{}', false) RETURNING *;

-- name: LockServerGrant :one
-- Org-scoped through deploy_targets.org_id (pre-flight ruling): locks only
-- the grant row (FOR UPDATE OF g) even though the target row is joined to
-- check org_id, so this never blocks a concurrent deploy-target update.
SELECT g.* FROM client_cert_grants g
JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.id = $1 AND g.client_id IS NULL AND g.removed_at IS NULL AND t.org_id = $2
FOR UPDATE OF g;

-- name: UpdateServerGrantLayout :one
-- A server grant's only editable field (Shared contract: updateGrant on a
-- server grant is layoutId only).
UPDATE client_cert_grants SET output_spec_id = sqlc.narg(output_spec_id), updated_at = now()
WHERE id = sqlc.arg(id) RETURNING *;

-- name: GrantRunsOn :one
-- Tells updateGrant/deleteGrant/redeployGrant which of the two grant kinds
-- id is, org-scoped through the matching join either way, in one round
-- trip; pgx.ErrNoRows means id is not a grant of orgId at all (either
-- kind), a 404. Deliberately no removed_at filter: deleteGrant must still
-- reach a removal-pending client grant (force, or its own soft-delete
-- confirmation path, both go through lockGrantAny); updateGrant and
-- redeployGrant 404 a removed grant themselves, through their own
-- downstream lock query (lockGrant, LockServerGrant), unchanged by this
-- routing step.
SELECT (CASE WHEN g.client_id IS NOT NULL THEN 'agent' ELSE 'server' END)::text AS runs_on
FROM client_cert_grants g
LEFT JOIN clients c ON c.id = g.client_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.id = $1
  AND ((g.client_id IS NOT NULL AND c.org_id = $2) OR (g.client_id IS NULL AND t.org_id = $2));

-- name: ServerGrantViews :many
SELECT g.id, g.deploy_target_id, g.cert_id, ce.name AS certificate_name, g.delivery,
       g.output_spec_id, g.hook_ids, g.auto_remediate, g.created_at, g.updated_at,
       sd.status, sd.version_id, sd.last_error, sd.deployed_at, sd.updated_at AS deployment_updated_at
FROM client_cert_grants g
JOIN deploy_targets t ON t.id = g.deploy_target_id
JOIN certificates ce ON ce.id = g.cert_id
LEFT JOIN server_deployments sd ON sd.grant_id = g.id
WHERE g.client_id IS NULL AND g.removed_at IS NULL AND t.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(target_id)::uuid IS NULL OR g.deploy_target_id = sqlc.narg(target_id)::uuid)
  AND (sqlc.narg(grant_id)::uuid IS NULL OR g.id = sqlc.narg(grant_id)::uuid)
ORDER BY lower(ce.name), g.id;

-- name: CertificateCurrentVersion :one
SELECT current_version_id FROM certificates WHERE id = $1;

-- name: CheckGrantRefs :one
SELECT
  EXISTS (SELECT 1 FROM certificates WHERE certificates.id = sqlc.arg(cert_id) AND certificates.org_id = sqlc.arg(org_id))::bool AS cert_ok,
  (sqlc.narg(layout_id)::uuid IS NULL OR EXISTS (SELECT 1 FROM output_specs WHERE output_specs.id = sqlc.narg(layout_id)::uuid AND output_specs.org_id = sqlc.arg(org_id)))::bool AS layout_ok,
  (sqlc.narg(target_id)::uuid IS NULL OR EXISTS (SELECT 1 FROM deploy_targets WHERE deploy_targets.id = sqlc.narg(target_id)::uuid AND deploy_targets.org_id = sqlc.arg(org_id)))::bool AS target_ok,
  (SELECT count(*) FROM hooks WHERE hooks.id = ANY(sqlc.arg(hook_ids)::uuid[]) AND hooks.org_id = sqlc.arg(org_id))::bigint AS hooks_found;
