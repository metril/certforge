-- +goose Up
CREATE TABLE api_keys (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix       text NOT NULL UNIQUE CHECK (prefix ~ '^[0-9a-f]{12}$'),
    secret_hash  bytea NOT NULL,
    scopes       text[] NOT NULL CHECK (cardinality(scopes) > 0),
    org_id       uuid REFERENCES orgs (id) ON DELETE CASCADE,
    created_by   uuid NOT NULL REFERENCES users (id),
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX api_keys_org ON api_keys (org_id);

-- +goose Down
DROP TABLE api_keys;
