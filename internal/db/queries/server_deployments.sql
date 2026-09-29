-- server_deployments: a server grant's own deploy state (Task 11), the
-- way deployments/agent reports do for an agent-run grant.

-- name: UpsertServerDeploymentPending :exec
-- Called whenever a server grant's target version changes (create, a new
-- certificate version via Dispatcher.OnVersion, or an explicit redeploy):
-- version_id is the version about to be deployed (nil for a certificate
-- with no version yet, C3), status resets to pending and any previous
-- error is cleared. deployed_at is left untouched (ON CONFLICT's SET list
-- omits it): the last successful deploy time survives a new pending cycle.
INSERT INTO server_deployments (grant_id, version_id, status, last_error, updated_at)
VALUES (sqlc.arg(grant_id), sqlc.narg(version_id), 'pending', '', now())
ON CONFLICT (grant_id) DO UPDATE SET version_id = EXCLUDED.version_id, status = 'pending',
       last_error = '', updated_at = now();

-- name: MarkServerDeploymentDeployed :exec
-- version_id is additionally checked (batch-5 review): a job for an older
-- version that finishes after a newer one has already taken over (pending
-- or deployed) must not overwrite server_deployments with stale state —
-- Dispatcher.Deploy also checks this before doing any work, so the
-- condition here is defense in depth against the same race, not the only
-- guard.
UPDATE server_deployments SET status = 'deployed', deployed_at = now(), last_error = '', updated_at = now()
WHERE grant_id = sqlc.arg(grant_id) AND version_id = sqlc.arg(version_id);

-- name: MarkServerDeploymentFailed :exec
-- last_error is the caller's own redacted, truncated (<=1000 chars) text
-- (internal/deploy.Dispatcher); never raw enough to carry a Vault token.
-- version_id is checked the same way as MarkServerDeploymentDeployed.
UPDATE server_deployments SET status = 'failed', last_error = sqlc.arg(last_error), updated_at = now()
WHERE grant_id = sqlc.arg(grant_id) AND version_id = sqlc.arg(version_id);

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
SELECT g.id, g.cert_id, g.deploy_target_id, t.org_id, o.slug AS org_slug, t.type AS target_type, t.config AS target_config,
       ce.name AS certificate_name, ce.common_name AS certificate_common_name, ce.sans AS certificate_sans,
       ce.current_version_id, ol.files AS layout_files, ol.password AS layout_password, ol.extra_cert_ids AS layout_extra_cert_ids,
       sd.version_id AS pending_version_id
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
