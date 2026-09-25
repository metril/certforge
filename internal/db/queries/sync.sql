-- name: ClientAssignments :many
SELECT g.id, g.cert_id, ce.name AS certificate_name, g.delivery, g.hook_ids, g.removed_at,
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
SELECT g.id, g.cert_id, ce.name AS certificate_name, d.version_id, o.files AS layout_files, t.type AS target_type
FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
JOIN deployments d ON d.grant_id = g.id
LEFT JOIN output_specs o ON o.id = g.output_spec_id
LEFT JOIN deploy_targets t ON t.id = g.deploy_target_id
WHERE g.id = sqlc.arg(id) AND g.client_id = sqlc.arg(client_id) AND g.removed_at IS NULL;

-- name: ClientDeployments :many
SELECT g.id AS grant_id, g.cert_id, g.delivery, g.auto_remediate, g.removed_at, d.state, d.version_id, d.expected
FROM client_cert_grants g JOIN deployments d ON d.grant_id = g.id
WHERE g.client_id = $1
ORDER BY g.id
FOR UPDATE OF d;

-- name: SetDeploymentState :exec
UPDATE deployments SET state = sqlc.arg(state), installed = sqlc.arg(installed), error = sqlc.arg(error),
       reported_at = now(), updated_at = now()
WHERE grant_id = sqlc.arg(grant_id);

-- name: InsertHookRun :exec
INSERT INTO hook_runs (client_id, grant_id, hook_id, phase, argv, exit_code, duration_ms, stdout, stderr)
VALUES (sqlc.arg(client_id), sqlc.arg(grant_id)::uuid, (SELECT h.id FROM hooks h WHERE h.id = sqlc.arg(hook_id)::uuid),
        sqlc.arg(phase), sqlc.arg(argv)::text[], sqlc.arg(exit_code), sqlc.arg(duration_ms), sqlc.arg(stdout), sqlc.arg(stderr));

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
