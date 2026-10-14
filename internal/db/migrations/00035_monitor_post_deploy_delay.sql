-- +goose Up
-- Seconds to wait after a server-grant deploy before its verify check runs;
-- post actions return before services finish reloading.
ALTER TABLE external_monitors ADD COLUMN post_deploy_delay_seconds int NOT NULL DEFAULT 15
    CHECK (post_deploy_delay_seconds BETWEEN 0 AND 600);

-- +goose Down
ALTER TABLE external_monitors DROP COLUMN post_deploy_delay_seconds;
