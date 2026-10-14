-- +goose Up
-- What the agent's file watcher reported in its last heartbeat; NULL until an
-- agent that has a watcher reports.
ALTER TABLE clients ADD COLUMN file_watch_active boolean, ADD COLUMN file_watch_reason text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE clients DROP COLUMN file_watch_reason, DROP COLUMN file_watch_active;
