-- +goose Up
-- OIDC groups from the user's last login; oidc_group role bindings match them.
ALTER TABLE users ADD COLUMN oidc_groups text[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE users DROP COLUMN oidc_groups;
