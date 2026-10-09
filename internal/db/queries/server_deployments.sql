-- server_deployments: a server grant's own deploy state (Task 11), the
-- way deployments/agent reports do for an agent-run grant.

-- name: UpsertServerDeploymentPending :one
-- Called whenever a server grant's target version changes (create, a new
-- certificate version via Dispatcher.OnVersion, or an explicit redeploy):
-- version_id is the version about to be deployed (nil for a certificate
-- with no version yet, C3), status resets to pending and any previous
-- error is cleared. deployed_at is left untouched (ON CONFLICT's SET list
-- omits it): the last successful deploy time survives a new pending cycle.
-- state_changed_at (final review fix wave, finding 1) moves with status
-- the same way deployments.state_changed_at does — CASE against the row's
-- own pre-update status, so a redeploy onto the same still-pending status
-- (an OnVersion for a version that never got picked up) does not reset it.
-- deploy_seq is bumped on every call and returned: it rides in the job args
-- (making a re-enqueue of the same version distinct from a running job) and
-- guards both Mark* queries against a stale job.
INSERT INTO server_deployments (grant_id, version_id, status, last_error, updated_at, state_changed_at, deploy_seq)
VALUES (sqlc.arg(grant_id), sqlc.narg(version_id), 'pending', '', now(), now(), 1)
ON CONFLICT (grant_id) DO UPDATE SET version_id = EXCLUDED.version_id, status = 'pending',
       last_error = '', updated_at = now(), deploy_seq = server_deployments.deploy_seq + 1,
       state_changed_at = CASE WHEN server_deployments.status IS DISTINCT FROM 'pending' THEN now() ELSE server_deployments.state_changed_at END
RETURNING deploy_seq;

-- name: MarkServerDeploymentDeployed :exec
-- version_id is additionally checked (batch-5 review): a job for an older
-- version that finishes after a newer one has already taken over (pending
-- or deployed) must not overwrite server_deployments with stale state —
-- Dispatcher.Deploy also checks this before doing any work, so the
-- condition here is defense in depth against the same race, not the only
-- guard. state_changed_at: same CASE convention as UpsertServerDeploymentPending.
UPDATE server_deployments SET status = 'deployed', deployed_at = now(), last_error = '', updated_at = now(),
       state_changed_at = CASE WHEN status IS DISTINCT FROM 'deployed' THEN now() ELSE state_changed_at END
WHERE grant_id = sqlc.arg(grant_id) AND version_id = sqlc.arg(version_id) AND deploy_seq = sqlc.arg(deploy_seq);

-- name: MarkServerDeploymentFailed :exec
-- last_error is the caller's own redacted, truncated (<=1000 chars) text
-- (internal/deploy.Dispatcher); never raw enough to carry a Vault token.
-- version_id is checked the same way as MarkServerDeploymentDeployed.
-- state_changed_at: same CASE convention (final review fix wave, finding
-- 1) — a job that fails repeatedly for the same still-failed status does
-- not keep pushing this forward, which is exactly what
-- ScanFailedServerDeployments needs to age a persistently-failing
-- deployment out of the retention window instead of re-emitting forever.
UPDATE server_deployments SET status = 'failed', last_error = sqlc.arg(last_error), updated_at = now(),
       state_changed_at = CASE WHEN status IS DISTINCT FROM 'failed' THEN now() ELSE state_changed_at END
WHERE grant_id = sqlc.arg(grant_id) AND version_id = sqlc.arg(version_id) AND deploy_seq = sqlc.arg(deploy_seq);

-- name: ServerDeployGrant :one
-- Everything DeployWorker needs for one grant_id, in a single round trip:
-- the target's type/config and its org's slug, the certificate's identity
-- and current version, its layout (if any), and the deployment's own
-- pending_version_id (batch-5 review: Dispatcher.Deploy compares this
-- against the job's own versionID and bails out, doing nothing, when they
-- differ — a stale job for an older version that finishes after a newer
-- one has already taken over must never overwrite it). Excludes a removed
-- or client-owned grant (pgx.ErrNoRows there means "nothing left to
-- deploy", not an error: the worker treats it as done).
-- Phase 7A Task 1: t.secret_cfg (a registry Target's Parse needs the
-- stored secrets to deploy) and t.name AS target_name (targets.Redact and
-- deploy.failed both name the target, never its raw config) are added for
-- the registry-driven dispatcher (Task 5).
SELECT g.id, g.cert_id, g.deploy_target_id, t.org_id, o.slug AS org_slug, t.type AS target_type, t.config AS target_config,
       t.secret_cfg AS target_secret_cfg, t.name AS target_name,
       ce.name AS certificate_name, ce.common_name AS certificate_common_name, ce.sans AS certificate_sans,
       ce.current_version_id, ol.files AS layout_files, ol.password AS layout_password, ol.extra_cert_ids AS layout_extra_cert_ids,
       sd.version_id AS pending_version_id, sd.deploy_seq AS pending_deploy_seq
FROM client_cert_grants g
JOIN deploy_targets t ON t.id = g.deploy_target_id
JOIN orgs o ON o.id = t.org_id
JOIN certificates ce ON ce.id = g.cert_id
LEFT JOIN output_specs ol ON ol.id = g.output_spec_id
LEFT JOIN server_deployments sd ON sd.grant_id = g.id
WHERE g.id = sqlc.arg(id) AND g.client_id IS NULL AND g.removed_at IS NULL;

-- name: LiveServerGrantIDsForCert :many
-- Dispatcher.OnVersion's own version of LiveGrantIDsForCert: every live
-- server grant of cert_id, never agents.Service's.
SELECT id FROM client_cert_grants WHERE cert_id = $1 AND removed_at IS NULL AND client_id IS NULL;

-- name: LiveServerGrantsForExtraCert :many
-- Dispatcher.OnVersion's own version of agents' LiveGrantIDsForExtraCert
-- (final review finding 5): live server grants whose layout bundles
-- cert_id as an extra certificate, with each grant's own certificate's
-- current_version_id — the version to redeploy is the grant's own
-- certificate's current version, not cert_id's (cert_id here is only the
-- extra certificate whose new version triggered this).
SELECT g.id, ce.current_version_id FROM client_cert_grants g
JOIN output_specs o ON o.id = g.output_spec_id
JOIN certificates ce ON ce.id = g.cert_id
WHERE g.removed_at IS NULL AND g.client_id IS NULL AND sqlc.arg(cert_id)::uuid = ANY(o.extra_cert_ids);

-- name: StaleServerDeployments :many
-- Dispatcher.SweepDeployments' safety net: live server grants whose
-- deployment is missing or not on the certificate's current version, or
-- that sit pending for over 15 minutes (a dropped river job) or failed for
-- over 6 hours (so a permanently failing target is not re-armed every cycle). Bounded.
SELECT g.id, ce.current_version_id FROM client_cert_grants g
JOIN certificates ce ON ce.id = g.cert_id
LEFT JOIN server_deployments sd ON sd.grant_id = g.id
WHERE g.removed_at IS NULL AND g.client_id IS NULL AND ce.current_version_id IS NOT NULL
  AND (sd.grant_id IS NULL
       OR sd.version_id IS DISTINCT FROM ce.current_version_id
       OR (sd.status = 'pending' AND sd.updated_at < now() - interval '15 minutes')
       OR (sd.status = 'failed' AND sd.updated_at < now() - interval '6 hours'))
ORDER BY sd.updated_at NULLS FIRST
LIMIT 200;
