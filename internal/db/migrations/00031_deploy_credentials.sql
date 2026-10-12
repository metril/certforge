-- +goose Up
-- Reusable, org-scoped credentials that deploy targets can reference instead
-- of embedding their own secret. Mirrors dns_provider_credentials.
CREATE TABLE deploy_credentials (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE,
    name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    kind               text NOT NULL CHECK (kind IN ('ssh', 'password', 'apiKey', 'token')),
    public             jsonb NOT NULL DEFAULT '{}',
    secret_cfg         bytea NOT NULL,            -- marshalled crypto.Blob of JSON map
    stored_secret_keys text[] NOT NULL DEFAULT '{}',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name),
    UNIQUE (org_id, id)
);

ALTER TABLE deploy_targets ADD COLUMN credential_id uuid;
ALTER TABLE deploy_targets ADD CONSTRAINT deploy_targets_credential_fk
    FOREIGN KEY (org_id, credential_id) REFERENCES deploy_credentials (org_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY IMMEDIATE;
CREATE INDEX deploy_targets_credential ON deploy_targets (credential_id) WHERE credential_id IS NOT NULL;

-- +goose Down
DROP INDEX deploy_targets_credential;
ALTER TABLE deploy_targets DROP CONSTRAINT deploy_targets_credential_fk;
ALTER TABLE deploy_targets DROP COLUMN credential_id;
DROP TABLE deploy_credentials;
