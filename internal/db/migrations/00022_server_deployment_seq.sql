-- +goose Up
-- deploy_seq is bumped on every UpsertServerDeploymentPending and carried in
-- the deploy job's args, so a re-enqueue for the same (grant, version) is not
-- dropped as a river duplicate while a stale job is running, and that stale
-- job cannot mark the row deployed.
ALTER TABLE server_deployments ADD COLUMN deploy_seq bigint NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE server_deployments DROP COLUMN deploy_seq;
