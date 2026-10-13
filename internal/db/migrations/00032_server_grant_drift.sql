-- +goose Up
-- Server grants gain a drift state (a grant-owned monitor saw a different
-- certificate), a flap guard for auto-remediation, and an optional
-- grant-owned external monitor.
ALTER TABLE server_deployments DROP CONSTRAINT server_deployments_status_check;
ALTER TABLE server_deployments ADD CONSTRAINT server_deployments_status_check
    CHECK (status IN ('pending', 'deployed', 'failed', 'drift'));
ALTER TABLE server_deployments ADD COLUMN remediations int NOT NULL DEFAULT 0, ADD COLUMN remediated_fp text;

ALTER TABLE external_monitors ADD COLUMN grant_id uuid UNIQUE REFERENCES client_cert_grants (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE;

-- +goose Down
ALTER TABLE external_monitors DROP COLUMN grant_id;
UPDATE server_deployments SET status = 'deployed' WHERE status = 'drift';
ALTER TABLE server_deployments DROP COLUMN remediated_fp, DROP COLUMN remediations;
ALTER TABLE server_deployments DROP CONSTRAINT server_deployments_status_check;
ALTER TABLE server_deployments ADD CONSTRAINT server_deployments_status_check
    CHECK (status IN ('pending', 'deployed', 'failed'));
