-- +goose Up
-- What the agent reported it could restart (heartbeat), for the hook target picker.
ALTER TABLE clients ADD COLUMN restart_targets jsonb NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE clients DROP COLUMN restart_targets;
