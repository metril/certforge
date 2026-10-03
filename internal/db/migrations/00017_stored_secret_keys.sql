-- +goose Up
-- The NAMES of the fields held in secret_cfg, kept in plaintext so listing
-- targets and channels does not have to decrypt every row (a Vault Transit
-- round trip each). Never values. Rows written before this migration keep an
-- empty array and are read by opening secret_cfg until their next write.
ALTER TABLE deploy_targets ADD COLUMN stored_secret_keys text[] NOT NULL DEFAULT '{}';
ALTER TABLE notification_channels ADD COLUMN stored_secret_keys text[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE notification_channels DROP COLUMN stored_secret_keys;
ALTER TABLE deploy_targets DROP COLUMN stored_secret_keys;
