-- +goose Up
-- One check-now webhook token per server grant. Kept apart from the grant row
-- so secrets never ride along on grant reads; deleting the row revokes it.
CREATE TABLE grant_check_tokens (
    grant_id    uuid PRIMARY KEY REFERENCES client_cert_grants (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE,
    prefix      text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  uuid, -- informational; no FK so user deletion never blocks
    last_used_at timestamptz
);

-- +goose Down
DROP TABLE grant_check_tokens;
