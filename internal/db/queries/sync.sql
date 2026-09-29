-- name: ClientAssignments :many
SELECT g.id, g.cert_id, ce.name AS certificate_name, ce.common_name AS certificate_common_name,
       ce.sans AS certificate_sans, g.delivery, g.hook_ids, g.removed_at, g.redeploy_seq,
       d.version_id, d.expected, cv.sha256_fp AS fingerprint, t.type AS target_type, t.config AS target_config
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
JOIN deployments d ON d.grant_id = g.id
LEFT JOIN certificate_versions cv ON cv.id = d.version_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.client_id = $1
ORDER BY g.created_at, g.id;

-- name: HooksByIDs :many
SELECT id, phase, argv, timeout_seconds FROM hooks WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: GrantForBundle :one
-- extra_version_ids (from the deployment, the last render) pairs with
-- layout_extra_cert_ids (from the layout, live) to render the bundle from
-- the versions actually last rendered, never the extra certificates'
-- current versions: see agents.Service.Bundle.
SELECT g.id, g.cert_id, ce.name AS certificate_name, d.version_id, o.files AS layout_files,
       o.password AS layout_password, o.extra_cert_ids AS layout_extra_cert_ids, d.extra_version_ids,
       t.type AS target_type
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
JOIN deployments d ON d.grant_id = g.id
LEFT JOIN output_specs o ON o.id = g.output_spec_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.id = sqlc.arg(id) AND g.client_id = sqlc.arg(client_id) AND g.removed_at IS NULL;

-- name: ClientDeployments :many
SELECT g.id AS grant_id, g.cert_id, g.delivery, g.auto_remediate, g.removed_at, g.removed_revision, d.state, d.version_id, d.expected
FROM client_cert_grants g JOIN deployments d ON d.grant_id = g.id
WHERE g.client_id = $1
ORDER BY g.id
FOR UPDATE OF d;

-- name: SetDeploymentState :exec
-- state_changed_at (final review fix wave, finding 1) moves only when
-- state actually transitions — the CASE compares against the row's own
-- pre-update state, which Postgres evaluates every SET expression
-- against regardless of clause order. updated_at still moves on every
-- report (agents.sync's own staleness/ordering uses it); the two are
-- deliberately no longer the same signal.
UPDATE deployments SET state = sqlc.arg(state), installed = sqlc.arg(installed), error = sqlc.arg(error),
       reported_at = now(), updated_at = now(),
       state_changed_at = CASE WHEN state IS DISTINCT FROM sqlc.arg(state) THEN now() ELSE state_changed_at END
WHERE grant_id = sqlc.arg(grant_id);

-- name: InsertHookRun :exec
-- hook_id is kept only when the agent-supplied id is one of the grant's own
-- hooks in the client's org; anything else is stored as NULL so a foreign
-- hook's name can never show up in this org's hook run history.
INSERT INTO hook_runs (client_id, grant_id, hook_id, phase, argv, exit_code, duration_ms, stdout, stderr)
VALUES (sqlc.arg(client_id), sqlc.arg(grant_id)::uuid,
        (SELECT h.id FROM hooks h
         WHERE h.id = sqlc.arg(hook_id)::uuid AND h.org_id = sqlc.arg(org_id)
           AND EXISTS (SELECT 1 FROM client_cert_grants g WHERE g.id = sqlc.arg(grant_id)::uuid AND h.id = ANY(g.hook_ids))),
        sqlc.arg(phase), sqlc.arg(argv)::text[], sqlc.arg(exit_code), sqlc.arg(duration_ms), sqlc.arg(stdout), sqlc.arg(stderr));

-- name: BumpRedeploySeqs :exec
-- Bumped by an explicit Redeploy and by server-side auto-remediation (a
-- heartbeat or report drift with auto_remediate): the agent is
-- level-triggered on the assignment (versionId, redeploySeq, and the file
-- list), never on-disk bytes, so this is what forces a redeploy when
-- nothing about the rendered files themselves changed.
UPDATE client_cert_grants SET redeploy_seq = redeploy_seq + 1, updated_at = now()
WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: SetAppliedRevision :exec
UPDATE clients SET applied_revision = GREATEST(applied_revision, LEAST(sqlc.arg(revision)::bigint, desired_revision)),
       last_seen = now()
WHERE id = sqlc.arg(id);

-- name: TouchClient :exec
UPDATE clients SET last_seen = now() WHERE id = $1;

-- name: ListHookRuns :many
SELECT r.id, r.client_id, r.grant_id, r.hook_id, r.phase, r.argv, r.exit_code, r.duration_ms, r.stdout, r.stderr, r.ran_at,
       COALESCE(h.name, '')::text AS hook_name
FROM hook_runs r LEFT JOIN hooks h ON h.id = r.hook_id
WHERE r.client_id = sqlc.arg(client_id)
  AND (NOT sqlc.arg(has_cursor)::bool OR (r.ran_at, r.id) < (sqlc.arg(before_ts)::timestamptz, sqlc.arg(before_id)::uuid))
ORDER BY r.ran_at DESC, r.id DESC
LIMIT sqlc.arg(page_limit)::int;
