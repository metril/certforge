-- +goose Up
-- Final review fix wave, finding 1: deployments.updated_at and
-- server_deployments.updated_at move on every agent report/deploy attempt,
-- even when the state itself does not change (SetDeploymentState always
-- sets updated_at = now(); the same is true of
-- MarkServerDeploymentDeployed/Failed). ScanFailedOrDriftedDeployments and
-- ScanFailedServerDeployments (internal/db/queries/notify.sql) use that
-- column to bound how far back a still-ongoing failure/drift is
-- considered "recent enough" not to have aged out of the 90-day event
-- retention window — with updated_at refreshed by every report, a
-- deployment stuck in failed/drift for more than 90 days never ages out,
-- so once its dedupe row is pruned, the next scan re-emits it, forever.
-- state_changed_at moves only when the row's own state/status actually
-- transitions (internal/db/queries/sync.sql SetDeploymentState,
-- internal/db/queries/server_deployments.sql), giving the scans a bound
-- that reflects the condition's own age, not how recently the agent last
-- reported.
ALTER TABLE deployments ADD COLUMN state_changed_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE server_deployments ADD COLUMN state_changed_at timestamptz NOT NULL DEFAULT now();

-- +goose Down
ALTER TABLE server_deployments DROP COLUMN state_changed_at;
ALTER TABLE deployments DROP COLUMN state_changed_at;
