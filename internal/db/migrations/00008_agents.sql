-- +goose Up
CREATE TABLE agent_cas (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_der   bytea NOT NULL,
    key        bytea NOT NULL, -- marshalled crypto.Blob of the PKCS#8 key
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retiring', 'retired')),
    not_before timestamptz NOT NULL,
    not_after  timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX agent_cas_one_active ON agent_cas (status) WHERE status = 'active';

CREATE TABLE clients (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id               uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    site_id              uuid REFERENCES sites (id) ON DELETE SET NULL,
    name                 text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    status               text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked')),
    agent_cert_serial    text NOT NULL DEFAULT '',
    agent_cert_not_after timestamptz,
    agent_ca_id          uuid REFERENCES agent_cas (id),
    hostname             text NOT NULL DEFAULT '',
    os                   text NOT NULL DEFAULT '',
    arch                 text NOT NULL DEFAULT '',
    agent_version        text NOT NULL DEFAULT '',
    capabilities         text[] NOT NULL DEFAULT '{}',
    last_seen            timestamptz,
    desired_revision     bigint NOT NULL DEFAULT 0,
    applied_revision     bigint NOT NULL DEFAULT 0,
    created_at           timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE INDEX clients_site ON clients (site_id);
CREATE INDEX clients_agent_ca ON clients (agent_ca_id);

CREATE TABLE enrollment_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id  uuid NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX enrollment_tokens_client ON enrollment_tokens (client_id);

CREATE TABLE output_specs (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    files      jsonb NOT NULL DEFAULT '[]', -- []delivery.OutputFile
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE deploy_targets (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    type       text NOT NULL CHECK (type IN ('traefik')),
    runs_on    text NOT NULL DEFAULT 'agent' CHECK (runs_on IN ('agent')),
    config     jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE hooks (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    phase           text NOT NULL CHECK (phase IN ('pre_deploy', 'post_deploy')),
    argv            text[] NOT NULL CHECK (cardinality(argv) BETWEEN 1 AND 64),
    timeout_seconds integer NOT NULL DEFAULT 60 CHECK (timeout_seconds BETWEEN 1 AND 3600),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE client_cert_grants (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id        uuid NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    cert_id          uuid NOT NULL REFERENCES certificates (id) ON DELETE CASCADE,
    delivery         text NOT NULL DEFAULT 'push' CHECK (delivery IN ('push', 'pull')),
    output_spec_id   uuid REFERENCES output_specs (id) ON DELETE RESTRICT,
    deploy_target_id uuid REFERENCES deploy_targets (id) ON DELETE RESTRICT,
    hook_ids         uuid[] NOT NULL DEFAULT '{}',
    auto_remediate   boolean NOT NULL DEFAULT false,
    removed_at       timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (output_spec_id IS NOT NULL OR deploy_target_id IS NOT NULL)
);
CREATE UNIQUE INDEX client_cert_grants_live ON client_cert_grants (client_id, cert_id) WHERE removed_at IS NULL;
CREATE INDEX client_cert_grants_cert ON client_cert_grants (cert_id);
CREATE INDEX client_cert_grants_layout ON client_cert_grants (output_spec_id);
CREATE INDEX client_cert_grants_target ON client_cert_grants (deploy_target_id);

CREATE TABLE deployments (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    grant_id    uuid NOT NULL UNIQUE REFERENCES client_cert_grants (id) ON DELETE CASCADE,
    version_id  uuid REFERENCES certificate_versions (id) ON DELETE SET NULL,
    state       text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'ok', 'failed', 'drift')),
    expected    jsonb NOT NULL DEFAULT '[]', -- []agentproto.FileSpec
    installed   jsonb NOT NULL DEFAULT '[]', -- []agentproto.FileDigest
    error       text NOT NULL DEFAULT '',
    reported_at timestamptz,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hook_runs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id   uuid NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    grant_id    uuid REFERENCES client_cert_grants (id) ON DELETE SET NULL,
    hook_id     uuid REFERENCES hooks (id) ON DELETE SET NULL,
    phase       text NOT NULL,
    argv        text[] NOT NULL DEFAULT '{}',
    exit_code   integer NOT NULL,
    duration_ms bigint NOT NULL DEFAULT 0,
    stdout      text NOT NULL DEFAULT '',
    stderr      text NOT NULL DEFAULT '',
    ran_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX hook_runs_client ON hook_runs (client_id, ran_at DESC, id DESC);

-- +goose Down
DROP TABLE hook_runs;
DROP TABLE deployments;
DROP TABLE client_cert_grants;
DROP TABLE hooks;
DROP TABLE deploy_targets;
DROP TABLE output_specs;
DROP TABLE enrollment_tokens;
DROP TABLE clients;
DROP TABLE agent_cas;
