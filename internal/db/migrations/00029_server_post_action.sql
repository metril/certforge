-- +goose Up
-- A server grant may run one command over SSH (through an existing ssh deploy
-- target) after a successful deploy. Server-side runs are recorded in
-- hook_runs with no client, against the grant's deploy target.
ALTER TABLE client_cert_grants ADD COLUMN post_action jsonb NOT NULL DEFAULT '{}';
ALTER TABLE hook_runs ALTER COLUMN client_id DROP NOT NULL;
ALTER TABLE hook_runs ADD COLUMN deploy_target_id uuid REFERENCES deploy_targets (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;
CREATE INDEX hook_runs_grant ON hook_runs (grant_id, ran_at DESC);
CREATE INDEX hook_runs_target ON hook_runs (deploy_target_id, ran_at DESC, id DESC) WHERE deploy_target_id IS NOT NULL;

-- +goose Down
DROP INDEX hook_runs_target;
DROP INDEX hook_runs_grant;
DELETE FROM hook_runs WHERE client_id IS NULL;
ALTER TABLE hook_runs DROP COLUMN deploy_target_id;
ALTER TABLE hook_runs ALTER COLUMN client_id SET NOT NULL;
ALTER TABLE client_cert_grants DROP COLUMN post_action;
