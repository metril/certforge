-- +goose Up
-- redeploy_seq is bumped by an explicit Redeploy and by server-side
-- auto-remediation (a heartbeat or report drift with auto_remediate): the
-- agent is level-triggered on the assignment (versionId, redeploy_seq, and
-- the file list), never on-disk bytes, so this is what forces a redeploy
-- when nothing about the rendered files themselves changed.
ALTER TABLE client_cert_grants ADD COLUMN redeploy_seq bigint NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE client_cert_grants DROP COLUMN redeploy_seq;
