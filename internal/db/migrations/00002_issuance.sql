-- +goose Up
CREATE TABLE cas (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name             text NOT NULL,
    type             text NOT NULL DEFAULT 'acme' CHECK (type IN ('acme')),
    preset           text NOT NULL,
    directory_url    text NOT NULL,
    trust_bundle_pem text NOT NULL DEFAULT '',
    eab_kid          text NOT NULL DEFAULT '',
    eab_hmac         bytea,                       -- marshalled crypto.Blob; NULL = no EAB
    resolvers        text[] NOT NULL DEFAULT '{}',
    shared           boolean NOT NULL DEFAULT false, -- global CAs arrive in Phase 2
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE acme_accounts (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ca_id            uuid NOT NULL REFERENCES cas(id) ON DELETE RESTRICT,
    email            text NOT NULL,
    account_key      bytea NOT NULL,              -- marshalled crypto.Blob of PKCS#8
    registration_uri text NOT NULL,
    status           text NOT NULL DEFAULT 'valid' CHECK (status IN ('valid', 'deactivated')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (ca_id, email)
);

CREATE TABLE dns_provider_credentials (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name          text NOT NULL,
    provider_code text NOT NULL,
    public_cfg    jsonb NOT NULL DEFAULT '{}',
    secret_cfg    bytea NOT NULL,                 -- marshalled crypto.Blob of JSON map
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- Org-scope defaults; global defaults live in settings key issuance_defaults.
CREATE TABLE issuance_defaults (
    org_id     uuid PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    config     jsonb NOT NULL DEFAULT '{}',       -- issuance.Defaults
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE certificates (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name               text NOT NULL,
    common_name        text NOT NULL,
    sans               text[] NOT NULL DEFAULT '{}',
    verification_rules jsonb NOT NULL DEFAULT '[]', -- []challenge.RuleSpec
    overrides          jsonb NOT NULL DEFAULT '{}', -- issuance.Defaults
    status             text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'active', 'failed', 'expired', 'revoked')),
    current_version_id uuid,
    next_renew_at      timestamptz,
    failure_count      integer NOT NULL DEFAULT 0,
    last_error         text NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE INDEX certificates_due_idx ON certificates (next_renew_at) WHERE next_renew_at IS NOT NULL;

CREATE TABLE certificate_versions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_id     uuid NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    serial      text NOT NULL,
    not_before  timestamptz NOT NULL,
    not_after   timestamptz NOT NULL,
    sha256_fp   text NOT NULL,
    key_type    text NOT NULL,
    leaf_der    bytea NOT NULL,
    chain_der   bytea[] NOT NULL DEFAULT '{}',
    private_key bytea NOT NULL,                   -- marshalled crypto.Blob of PKCS#8
    source      text NOT NULL DEFAULT 'issued' CHECK (source IN ('issued', 'imported', 'uploaded')),
    ari_window  jsonb,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX certificate_versions_cert_idx ON certificate_versions (cert_id, created_at DESC);
ALTER TABLE certificates ADD CONSTRAINT certificates_current_version_fk
    FOREIGN KEY (current_version_id) REFERENCES certificate_versions(id) ON DELETE SET NULL;

CREATE TABLE issuance_attempts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_id         uuid NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    outcome         text NOT NULL DEFAULT 'running' CHECK (outcome IN ('running', 'success', 'failed')),
    acme_error_type text NOT NULL DEFAULT '',
    retry_after     timestamptz,
    steps           jsonb NOT NULL DEFAULT '[]',
    log             text NOT NULL DEFAULT ''
);
CREATE INDEX issuance_attempts_cert_idx ON issuance_attempts (cert_id, started_at DESC);

CREATE TABLE manual_dns_pending (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    attempt_id   uuid NOT NULL REFERENCES issuance_attempts(id) ON DELETE CASCADE,
    cert_id      uuid NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    domain       text NOT NULL,
    fqdn         text NOT NULL,
    value        text NOT NULL,
    ttl          integer NOT NULL,
    expires_at   timestamptz NOT NULL,
    confirmed_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX manual_dns_pending_cert_idx ON manual_dns_pending (cert_id);

-- +goose Down
DROP TABLE manual_dns_pending;
DROP TABLE issuance_attempts;
ALTER TABLE certificates DROP CONSTRAINT certificates_current_version_fk;
DROP TABLE certificate_versions;
DROP TABLE certificates;
DROP TABLE issuance_defaults;
DROP TABLE dns_provider_credentials;
DROP TABLE acme_accounts;
DROP TABLE cas;
