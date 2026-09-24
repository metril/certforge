-- +goose Up
CREATE TABLE orgs (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sites (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE users (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    oidc_issuer         text,
    oidc_sub            text,
    email               text,
    display_name        text NOT NULL DEFAULT '',
    local_password_hash text,
    disabled            boolean NOT NULL DEFAULT false,
    last_login          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (oidc_issuer, oidc_sub)
);
-- At most one local (break-glass) admin.
CREATE UNIQUE INDEX users_one_local_admin ON users ((local_password_hash IS NOT NULL))
    WHERE local_password_hash IS NOT NULL;

CREATE TABLE sessions (
    id         text PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf       text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_expires_at ON sessions (expires_at);

CREATE TABLE role_bindings (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_type text NOT NULL CHECK (subject_type IN ('user', 'oidc_group', 'apikey')),
    subject      text NOT NULL,
    role         text NOT NULL CHECK (role IN ('admin', 'org-admin', 'operator', 'viewer', 'auditor')),
    org_id       uuid REFERENCES orgs (id) ON DELETE CASCADE,
    site_id      uuid REFERENCES sites (id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX role_bindings_unique ON role_bindings (
    subject_type, subject, role,
    COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid),
    COALESCE(site_id, '00000000-0000-0000-0000-000000000000'::uuid)
);

CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL DEFAULT 'null'::jsonb,
    secret     bytea,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    id            bigserial PRIMARY KEY,
    ts            timestamptz NOT NULL,
    actor_type    text NOT NULL,
    actor_id      text NOT NULL DEFAULT '',
    action        text NOT NULL,
    resource_type text NOT NULL,
    resource_id   text NOT NULL DEFAULT '',
    org_id        uuid,
    ip            text NOT NULL DEFAULT '',
    details       jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_hash     bytea NOT NULL UNIQUE,
    hash          bytea NOT NULL
);
CREATE INDEX audit_events_org_ts ON audit_events (org_id, ts DESC);

-- +goose StatementBegin
CREATE FUNCTION audit_events_block_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER audit_events_immutable
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_block_mutation();
CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_block_mutation();

-- +goose Down
DROP TABLE audit_events;
DROP FUNCTION audit_events_block_mutation();
DROP TABLE settings;
DROP TABLE role_bindings;
DROP TABLE sessions;
DROP TABLE users;
DROP TABLE sites;
DROP TABLE orgs;
