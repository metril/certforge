-- name: CreateGrant :one
INSERT INTO client_cert_grants (client_id, cert_id, delivery, output_spec_id, deploy_target_id, steps, auto_remediate, target_options)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *;

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
       deploy_target_id = sqlc.narg(deploy_target_id), steps = sqlc.arg(steps),
       auto_remediate = sqlc.arg(auto_remediate), target_options = COALESCE(sqlc.narg(target_options), target_options), updated_at = now()
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
-- Optional AND filters. The steps predicates match LiveGrantIDsUsingAction /
-- LiveGrantIDsUsingActionGroup (action direct, or through a group).
SELECT g.id, g.client_id, c.name AS client_name, g.cert_id, ce.name AS certificate_name, g.delivery,
       g.output_spec_id, g.deploy_target_id, g.steps, g.auto_remediate, g.target_options, g.created_at, g.updated_at,
       o.name AS layout_name, t.name AS deploy_target_name,
       d.state, d.version_id, d.expected, d.installed, d.error, d.reported_at, d.state_changed_at, d.updated_at AS deployment_updated_at
FROM client_cert_grants g
JOIN clients c ON c.id = g.client_id
JOIN certificates ce ON ce.id = g.cert_id
JOIN deployments d ON d.grant_id = g.id
LEFT JOIN output_specs o ON o.id = g.output_spec_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE c.org_id = sqlc.arg(org_id) AND g.removed_at IS NULL
  AND (sqlc.narg(client_id)::uuid IS NULL OR g.client_id = sqlc.narg(client_id)::uuid)
  AND (sqlc.narg(grant_id)::uuid IS NULL OR g.id = sqlc.narg(grant_id)::uuid)
  AND (sqlc.narg(cert_id)::uuid IS NULL OR g.cert_id = sqlc.narg(cert_id)::uuid)
  AND (sqlc.narg(layout_id)::uuid IS NULL OR g.output_spec_id = sqlc.narg(layout_id)::uuid)
  AND (sqlc.narg(target_id)::uuid IS NULL OR g.deploy_target_id = sqlc.narg(target_id)::uuid)
  AND (sqlc.narg(action_id)::uuid IS NULL
       OR g.steps @> jsonb_build_array(jsonb_build_object('action', sqlc.narg(action_id)::uuid))
       OR EXISTS (SELECT 1 FROM action_groups ag
                  WHERE ag.action_ids @> ARRAY[sqlc.narg(action_id)::uuid]
                    AND g.steps @> jsonb_build_array(jsonb_build_object('group', ag.id))))
  AND (sqlc.narg(group_id)::uuid IS NULL
       OR g.steps @> jsonb_build_array(jsonb_build_object('group', sqlc.narg(group_id)::uuid)))
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
-- t.secret_cfg AS target_secret_cfg (Phase 7A Task 6): Service.render opens
-- it and merges it into the target's config the same way Assignments does
-- (ClientAssignments' own comment), so a grant's expected file set
-- (targets.GrantFiles) is computed from the same fully resolved config the
-- agent will actually render from — never out of step with it because a
-- future FileTarget's Files happened to need a secret field.
-- Reused by LiveGrantsNeedKeyTx, which ignores the new column
-- (NeedsKey only ever needs the public config).
SELECT g.id, g.client_id, g.cert_id, g.delivery, ce.name AS certificate_name,
       ce.common_name AS certificate_common_name, ce.sans AS certificate_sans, ce.current_version_id,
       o.files AS layout_files, o.password AS layout_password, o.extra_cert_ids AS layout_extra_cert_ids,
       t.type AS target_type, t.config AS target_config, t.secret_cfg AS target_secret_cfg, g.target_options, dc.kind AS credential_kind, dc.public AS credential_public, dc.secret_cfg AS credential_secret_cfg
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
LEFT JOIN output_specs o ON o.id = g.output_spec_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
LEFT JOIN deploy_credentials dc ON dc.id = t.credential_id
WHERE g.id = ANY(sqlc.arg(ids)::uuid[]) AND g.removed_at IS NULL;

-- name: LiveGrantIDsForCert :many
-- client_id IS NOT NULL: a server grant (Task 11) is deployed by
-- internal/deploy.Dispatcher, its own issuance.VersionListener, never by
-- agents.Service.render/OnVersion (clientOf's doc comment).
SELECT id FROM client_cert_grants WHERE cert_id = $1 AND removed_at IS NULL AND client_id IS NOT NULL;

-- name: LiveGrantIDsForCertAny :many
-- LiveGrantsNeedKeyTx's own version of LiveGrantIDsForCert (final review
-- finding 3): every live grant of cert_id, agent-run or server-run alike.
-- A server grant needs a key too (its target's own includeKey, or its
-- layout's), so the keyless-upload gate must see it — unlike every other
-- caller of "live grants of a cert" in this file, which must keep
-- excluding server grants (see LiveGrantIDsForCert's own comment).
SELECT id FROM client_cert_grants WHERE cert_id = $1 AND removed_at IS NULL;

-- name: LiveGrantIDsForExtraCert :many
-- Live grants whose layout bundles cert_id as an extra certificate: a new
-- version of an extra certificate must re-render these grants too, not
-- only the grants of cert_id's own certificate. client_id IS NOT NULL: see
-- LiveGrantIDsForCert.
SELECT g.id FROM client_cert_grants g
JOIN output_specs o ON o.id = g.output_spec_id
WHERE g.removed_at IS NULL AND g.client_id IS NOT NULL AND o.extra_cert_ids @> ARRAY[sqlc.arg(cert_id)::uuid];

-- name: LiveGrantIDsUsingLayout :many
-- client_id IS NOT NULL: see LiveGrantIDsForCert.
SELECT id FROM client_cert_grants WHERE output_spec_id = $1 AND removed_at IS NULL AND client_id IS NOT NULL;

-- name: LiveGrantIDsUsingTarget :many
-- client_id IS NOT NULL: a server grant's deploy_target_id names the
-- server-run target itself (not an agent-side Traefik target), and its
-- redeploy path never goes through agents.Resync; see LiveGrantIDsForCert.
SELECT id FROM client_cert_grants WHERE deploy_target_id = $1 AND removed_at IS NULL AND client_id IS NOT NULL;

-- name: ServerGrantsUsingLayout :many
-- UpdateLayout's own version of LiveGrantIDsUsingLayout (batch-5 review):
-- every live server grant using layout_id, with its certificate's current
-- version, so UpdateLayout can refuse a non-PEM update while one exists
-- and, once an allowed update commits, redeploy each of them.
SELECT g.id, ce.current_version_id
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
WHERE g.output_spec_id = sqlc.arg(layout_id)::uuid AND g.removed_at IS NULL AND g.client_id IS NULL;

-- name: ServerGrantsUsingTarget :many
-- UpdateDeployTarget's own version of LiveGrantIDsUsingTarget: every live
-- server grant on target_id, with its certificate's current version, so a
-- target edit can redeploy each of them in the same transaction.
SELECT g.id, ce.current_version_id
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
WHERE g.deploy_target_id = sqlc.arg(target_id)::uuid AND g.removed_at IS NULL AND g.client_id IS NULL;

-- name: LiveGrantIDsUsingAction :many
-- Live client grants whose steps name the action directly or through one of
-- the given group ids (the groups that contain it).
-- client_id IS NOT NULL: see LiveGrantIDsForCert.
SELECT id FROM client_cert_grants
WHERE (steps @> jsonb_build_array(jsonb_build_object('action', sqlc.arg(action_id)::uuid))
       OR EXISTS (SELECT 1 FROM action_groups ag
                  WHERE ag.action_ids @> ARRAY[sqlc.arg(action_id)::uuid]
                    AND steps @> jsonb_build_array(jsonb_build_object('group', ag.id))))
  AND removed_at IS NULL AND client_id IS NOT NULL;

-- name: LiveGrantIDsUsingActionGroup :many
-- Live client grants whose steps name the group.
SELECT id FROM client_cert_grants
WHERE steps @> jsonb_build_array(jsonb_build_object('group', sqlc.arg(group_id)::uuid))
  AND removed_at IS NULL AND client_id IS NOT NULL;

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
       t.type AS target_type, t.config AS target_config, g.target_options, d.expected
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
            -- The correlated subquery runs only for grants whose layout has
            -- extras; every other grant (including one with no layout) takes
            -- the cheap branch, whose value is what the subquery would give.
            CASE WHEN cardinality(o.extra_cert_ids) > 0 THEN (
              SELECT COALESCE(array_agg(ec.current_version_id ORDER BY x.ord), '{}'::uuid[])
              FROM unnest(o.extra_cert_ids) WITH ORDINALITY AS x(id, ord)
              JOIN certificates ec ON ec.id = x.id
            ) ELSE '{}'::uuid[] END
          ));

-- name: LockActionsInOrg :many
-- Locks the org's actions referenced by ids FOR SHARE, so a concurrent
-- DeleteAction (which locks the action row FOR UPDATE before deleting)
-- either blocks until this transaction commits and then sees the new grant
-- among its dependents, or has already committed the delete and this
-- transaction sees fewer rows than ids, and the caller rejects the grant.
-- steps has no FK (it is plain JSON), so this lock is what keeps an id from
-- going dangling.
SELECT id FROM actions WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND org_id = sqlc.arg(org_id) FOR SHARE;

-- name: LockActionGroupsInOrg :many
-- Same as LockActionsInOrg, for the groups a grant's steps name.
SELECT id, action_ids FROM action_groups WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND org_id = sqlc.arg(org_id) FOR SHARE;

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
-- schedule for a server grant), steps carries its actions and groups.
INSERT INTO client_cert_grants (client_id, cert_id, delivery, output_spec_id, deploy_target_id, steps, auto_remediate, target_options)
VALUES (NULL, sqlc.arg(cert_id), 'push', sqlc.narg(output_spec_id), sqlc.narg(deploy_target_id), COALESCE(sqlc.narg(steps)::jsonb, '[]'), sqlc.arg(auto_remediate), COALESCE(sqlc.narg(target_options)::jsonb, '{}')) RETURNING *;

-- name: LockServerGrant :one
-- Org-scoped through deploy_targets.org_id (pre-flight ruling): locks only
-- the grant row (FOR UPDATE OF g) even though the target row is joined to
-- check org_id, so this never blocks a concurrent deploy-target update.
SELECT g.* FROM client_cert_grants g
JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.id = $1 AND g.client_id IS NULL AND g.removed_at IS NULL AND t.org_id = $2
FOR UPDATE OF g;

-- name: UpdateServerGrant :one
-- A server grant's editable fields: its layout, auto-remediate flag, steps and target options.
UPDATE client_cert_grants SET output_spec_id = sqlc.narg(output_spec_id), auto_remediate = sqlc.arg(auto_remediate), steps = COALESCE(sqlc.narg(steps)::jsonb, '[]'), target_options = COALESCE(sqlc.narg(target_options)::jsonb, '{}'), updated_at = now()
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
-- Same optional filters as GrantViews (minus client).
SELECT g.id, g.deploy_target_id, g.cert_id, ce.name AS certificate_name, g.delivery,
       g.output_spec_id, g.steps, g.auto_remediate, g.target_options, g.created_at, g.updated_at,
       o.name AS layout_name, t.name AS deploy_target_name,
       sd.status, sd.version_id, sd.last_error, sd.deployed_at, sd.updated_at AS deployment_updated_at,
       m.id AS monitor_id, m.host, m.port, m.sni, m.interval_seconds, m.post_deploy_delay_seconds,
       EXISTS (SELECT 1 FROM grant_check_tokens ct WHERE ct.grant_id = g.id)::bool AS check_token_set
FROM client_cert_grants g
JOIN deploy_targets t ON t.id = g.deploy_target_id
JOIN certificates ce ON ce.id = g.cert_id
LEFT JOIN output_specs o ON o.id = g.output_spec_id
LEFT JOIN server_deployments sd ON sd.grant_id = g.id
LEFT JOIN external_monitors m ON m.grant_id = g.id
WHERE g.client_id IS NULL AND g.removed_at IS NULL AND t.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(target_id)::uuid IS NULL OR g.deploy_target_id = sqlc.narg(target_id)::uuid)
  AND (sqlc.narg(grant_id)::uuid IS NULL OR g.id = sqlc.narg(grant_id)::uuid)
  AND (sqlc.narg(cert_id)::uuid IS NULL OR g.cert_id = sqlc.narg(cert_id)::uuid)
  AND (sqlc.narg(layout_id)::uuid IS NULL OR g.output_spec_id = sqlc.narg(layout_id)::uuid)
  AND (sqlc.narg(action_id)::uuid IS NULL
       OR g.steps @> jsonb_build_array(jsonb_build_object('action', sqlc.narg(action_id)::uuid))
       OR EXISTS (SELECT 1 FROM action_groups ag
                  WHERE ag.action_ids @> ARRAY[sqlc.narg(action_id)::uuid]
                    AND g.steps @> jsonb_build_array(jsonb_build_object('group', ag.id))))
  AND (sqlc.narg(group_id)::uuid IS NULL
       OR g.steps @> jsonb_build_array(jsonb_build_object('group', sqlc.narg(group_id)::uuid)))
ORDER BY lower(ce.name), g.id;

-- name: CertificateCurrentVersion :one
SELECT current_version_id FROM certificates WHERE id = $1;

-- name: CheckGrantRefs :one
SELECT
  EXISTS (SELECT 1 FROM certificates WHERE certificates.id = sqlc.arg(cert_id) AND certificates.org_id = sqlc.arg(org_id))::bool AS cert_ok,
  (sqlc.narg(layout_id)::uuid IS NULL OR EXISTS (SELECT 1 FROM output_specs WHERE output_specs.id = sqlc.narg(layout_id)::uuid AND output_specs.org_id = sqlc.arg(org_id)))::bool AS layout_ok,
  (sqlc.narg(target_id)::uuid IS NULL OR EXISTS (SELECT 1 FROM deploy_targets WHERE deploy_targets.id = sqlc.narg(target_id)::uuid AND deploy_targets.org_id = sqlc.arg(org_id)))::bool AS target_ok,
  (SELECT count(*) FROM actions WHERE actions.id = ANY(sqlc.arg(action_ids)::uuid[]) AND actions.org_id = sqlc.arg(org_id))::bigint AS actions_found;

-- name: CountPostActionUsers :one
-- Live server grants with a step whose action runs on this target.
SELECT count(DISTINCT g.id)::bigint FROM client_cert_grants g
JOIN actions a ON g.steps @> jsonb_build_array(jsonb_build_object('action', a.id))
WHERE g.removed_at IS NULL AND g.client_id IS NULL AND a.config->>'targetId' = sqlc.arg(id)::text;

-- name: LiveGrantSidesUsingActionGroup :many
-- Distinct sides (true = server grant, false = client grant) of the live
-- grants whose steps name the group.
SELECT DISTINCT (deploy_target_id IS NOT NULL)::bool AS server FROM client_cert_grants
WHERE steps @> jsonb_build_array(jsonb_build_object('group', sqlc.arg(group_id)::uuid))
  AND removed_at IS NULL;

-- name: UpsertGrantCheckToken :exec
-- Generate or rotate: replaces any earlier token for the grant.
INSERT INTO grant_check_tokens (grant_id, prefix, secret_hash, created_by)
VALUES (sqlc.arg(grant_id), sqlc.arg(prefix), sqlc.arg(secret_hash), sqlc.narg(created_by))
ON CONFLICT (grant_id) DO UPDATE
SET prefix = EXCLUDED.prefix, secret_hash = EXCLUDED.secret_hash, created_by = EXCLUDED.created_by,
    created_at = now(), last_used_at = NULL;

-- name: GetGrantCheckTokenByPrefix :one
-- Live (not soft-removed) server grants only; org_id comes from the target.
SELECT ct.grant_id, ct.secret_hash, t.org_id
FROM grant_check_tokens ct
JOIN client_cert_grants g ON g.id = ct.grant_id AND g.removed_at IS NULL AND g.client_id IS NULL
JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE ct.prefix = $1;

-- name: DeleteGrantCheckToken :execrows
DELETE FROM grant_check_tokens WHERE grant_id = $1;

-- name: TouchGrantCheckToken :exec
UPDATE grant_check_tokens SET last_used_at = now() WHERE grant_id = $1;
