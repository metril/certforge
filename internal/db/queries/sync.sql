-- name: ClientAssignments :many
-- t.secret_cfg AS target_secret_cfg (Phase 7A Task 6): agents.Service.Assignments
-- opens it and merges it back into the target's public config
-- (targets.Merge) before sending Target.Config to the agent — the same
-- fully resolved shape a server-side Request.Config carries
-- (Dispatcher.Deploy) — so a registry-driven FileTarget's Files/Paths/
-- Reload see any secret fields it has, not just traefik/vault-kv's own
-- (neither has one today).
SELECT g.id, g.cert_id, ce.name AS certificate_name, ce.common_name AS certificate_common_name,
       ce.sans AS certificate_sans, g.delivery, g.steps, g.removed_at, g.redeploy_seq,
       d.version_id, d.expected, cv.sha256_fp AS fingerprint, t.type AS target_type, t.config AS target_config,
       t.secret_cfg AS target_secret_cfg, g.target_options, dc.kind AS credential_kind, dc.public AS credential_public, dc.secret_cfg AS credential_secret_cfg
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
JOIN deployments d ON d.grant_id = g.id
LEFT JOIN certificate_versions cv ON cv.id = d.version_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
LEFT JOIN deploy_credentials dc ON dc.id = t.credential_id
WHERE g.client_id = $1
ORDER BY g.created_at, g.id;

-- name: ActionsByIDs :many
SELECT id, phase, kind, config, timeout_seconds, optional FROM actions WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: ActionGroupsByIDs :many
SELECT id, action_ids FROM action_groups WHERE id = ANY(sqlc.arg(ids)::uuid[]);

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
SELECT g.id AS grant_id, g.cert_id, g.delivery, g.auto_remediate, g.removed_at, g.removed_revision, d.state, d.version_id, d.expected, ce.name AS certificate_name
FROM client_cert_grants g JOIN deployments d ON d.grant_id = g.id
JOIN certificates ce ON ce.id = g.cert_id
WHERE g.client_id = $1
ORDER BY g.id
FOR UPDATE OF d;

-- name: ClientDeploymentsNoLock :many
-- ClientDeployments without the row locks: Heartbeat reads with this first
-- and takes the locked path only when a state would change.
SELECT g.id AS grant_id, g.cert_id, g.delivery, g.auto_remediate, g.removed_at, g.removed_revision, d.state, d.version_id, d.expected, ce.name AS certificate_name
FROM client_cert_grants g JOIN deployments d ON d.grant_id = g.id
JOIN certificates ce ON ce.id = g.cert_id
WHERE g.client_id = $1
ORDER BY g.id;

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
-- actions in the client's org (named directly or through a group); anything
-- else is stored as NULL so a foreign action's name can never show up in this
-- org's run history.
INSERT INTO hook_runs (client_id, grant_id, hook_id, phase, argv, exit_code, duration_ms, stdout, stderr)
VALUES (sqlc.arg(client_id), sqlc.arg(grant_id)::uuid,
        (SELECT h.id FROM actions h
         WHERE h.id = sqlc.arg(hook_id)::uuid AND h.org_id = sqlc.arg(org_id)
           AND EXISTS (SELECT 1 FROM client_cert_grants g WHERE g.id = sqlc.arg(grant_id)::uuid
                       AND (g.steps @> jsonb_build_array(jsonb_build_object('action', h.id))
                            OR EXISTS (SELECT 1 FROM action_groups ag WHERE ag.action_ids @> ARRAY[h.id]
                                       AND g.steps @> jsonb_build_array(jsonb_build_object('group', ag.id)))))),
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

-- name: TouchClient :one
-- Returns the client's identity and its previous last_seen (NULL before the
-- first check-in), read under the row lock so concurrent touches see distinct values.
UPDATE clients c SET last_seen = now()
FROM (SELECT p.id, p.last_seen FROM clients p WHERE p.id = $1 FOR UPDATE) prev
WHERE c.id = prev.id
RETURNING c.org_id, c.name, prev.last_seen AS prev_last_seen;

-- name: ListHookRuns :many
SELECT r.id, r.client_id, r.grant_id, r.hook_id, r.phase, r.argv, r.exit_code, r.duration_ms, r.stdout, r.stderr, r.ran_at,
       COALESCE(h.name, '')::text AS action_name, COALESCE(h.kind, '')::text AS action_kind
FROM hook_runs r LEFT JOIN actions h ON h.id = r.hook_id
WHERE r.client_id = sqlc.arg(client_id)
  AND (NOT sqlc.arg(has_cursor)::bool OR (r.ran_at, r.id) < (sqlc.arg(before_ts)::timestamptz, sqlc.arg(before_id)::uuid))
ORDER BY r.ran_at DESC, r.id DESC
LIMIT sqlc.arg(page_limit)::int;

-- name: PruneHookRuns :execrows
-- Deletes at most batch_limit hook runs older than the retention cutoff;
-- run by the 5-minute certforge_schedule job.
DELETE FROM hook_runs WHERE id IN (
  SELECT h.id FROM hook_runs h WHERE h.ran_at < sqlc.arg(before) LIMIT sqlc.arg(batch_limit)::int
);

-- name: InsertServerHookRun :exec
-- A server-side run (the ssh target's own pre/post command, or a grant's
-- post action): no client, tied to the grant and its deploy target.
INSERT INTO hook_runs (client_id, grant_id, hook_id, deploy_target_id, phase, argv, exit_code, duration_ms, stdout, stderr)
VALUES (NULL, sqlc.narg(grant_id)::uuid, sqlc.narg(hook_id)::uuid, sqlc.arg(deploy_target_id), sqlc.arg(phase), sqlc.arg(argv)::text[],
        sqlc.arg(exit_code), sqlc.arg(duration_ms), sqlc.arg(stdout), sqlc.arg(stderr));

-- name: ListTargetHookRuns :many
SELECT r.id, r.grant_id, r.hook_id, r.phase, r.argv, r.exit_code, r.duration_ms, r.stdout, r.stderr, r.ran_at,
       COALESCE(h.name, '')::text AS action_name, COALESCE(h.kind, '')::text AS action_kind
FROM hook_runs r LEFT JOIN actions h ON h.id = r.hook_id
WHERE r.deploy_target_id = sqlc.arg(deploy_target_id)
  AND (NOT sqlc.arg(has_cursor)::bool OR (r.ran_at, r.id) < (sqlc.arg(before_ts)::timestamptz, sqlc.arg(before_id)::uuid))
ORDER BY r.ran_at DESC, r.id DESC
LIMIT sqlc.arg(page_limit)::int;
