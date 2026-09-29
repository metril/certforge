-- +goose Up
-- Phase 6A Task 1: notification channels, events and deliveries; external
-- monitors (Shared contracts, Channel/Event/Monitor operations rows).
-- secret_cfg on notification_channels holds a marshalled crypto.Blob for
-- write-only channel fields (webhook url/authHeader/signingSecret, discord
-- webhookUrl, ntfy token, homeassistant webhookId) the same way cas.secret_cfg
-- and dns_provider_credentials.secret_cfg already do.
CREATE TABLE notification_channels (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    type         text NOT NULL CHECK (type IN ('webhook', 'smtp', 'discord', 'ntfy', 'homeassistant')),
    config       jsonb NOT NULL DEFAULT '{}',
    secret_cfg   bytea,
    events       text[] NOT NULL DEFAULT '{}',
    min_severity text NOT NULL DEFAULT 'info' CHECK (min_severity IN ('info', 'warning', 'critical')),
    all_orgs     boolean NOT NULL DEFAULT false,
    enabled      boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
-- listChannels' allOrgs lookup (Shared contract, Channel operations row)
-- scans only the channels that opt into cross-org delivery.
CREATE INDEX notification_channels_all_orgs ON notification_channels (all_orgs) WHERE all_orgs;

-- org_id is nullable: a global event (backup.*, and any future org-less
-- kind) has none. dedupe_key is the exact-once guard Emit relies on
-- (Deviations R5/notify Dedupe keys row): a UNIQUE violation on insert means
-- this condition already fired and Emit treats it as a no-op.
CREATE TABLE notification_events (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid REFERENCES orgs (id) ON DELETE CASCADE,
    kind          text NOT NULL CHECK (kind IN (
        'cert.issued', 'cert.renewal_failed', 'cert.expiring', 'cert.expired',
        'deploy.failed', 'deploy.drift', 'client.offline', 'agent.cert_expiring',
        'monitor.mismatch', 'monitor.unreachable', 'monitor.expiring', 'monitor.recovered',
        'backup.completed', 'backup.failed', 'test'
    )),
    severity      text NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    resource_type text NOT NULL CHECK (resource_type IN ('certificate', 'grant', 'client', 'monitor', 'backup', 'channel')),
    resource_id   text NOT NULL DEFAULT '',
    resource_name text NOT NULL DEFAULT '',
    summary       text NOT NULL CHECK (length(summary) <= 500),
    details       jsonb NOT NULL DEFAULT '{}',
    dedupe_key    text NOT NULL UNIQUE,
    at            timestamptz NOT NULL DEFAULT now()
);
-- listEvents' feed (Shared contract, Other operations row: the org's events
-- plus global orgId: null events, newest first).
CREATE INDEX notification_events_org_at ON notification_events (org_id, at DESC, id DESC);
-- The 90-day event prune (Deviations R2) walks by age alone.
CREATE INDEX notification_events_at ON notification_events (at);

-- One row per (event, matched channel): DeliverWorker's own unit of work,
-- and lastDelivery's source (Shared contract, Channel schema).
CREATE TABLE notification_deliveries (
    event_id     uuid NOT NULL REFERENCES notification_events (id) ON DELETE CASCADE,
    channel_id   uuid NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    attempts     int NOT NULL DEFAULT 0,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed')),
    last_error   text NOT NULL DEFAULT '' CHECK (length(last_error) <= 1000),
    delivered_at timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, channel_id)
);
-- A channel's lastDelivery (Shared contract, Channel schema) is its most
-- recently updated delivery row.
CREATE INDEX notification_deliveries_channel_updated ON notification_deliveries (channel_id, updated_at DESC);

-- state_changed_at (Deviations R5) backs the monitor dedupe key
-- monitor.<state>:<id>:<fp>:<state_changed_at unix>, so a transition emits
-- exactly once even across two racing checks (a compare-and-set on state).
CREATE TABLE external_monitors (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    host             text NOT NULL CHECK (length(host) <= 253),
    port             int NOT NULL DEFAULT 443 CHECK (port BETWEEN 1 AND 65535),
    sni              text CHECK (sni IS NULL OR length(sni) <= 253),
    interval_seconds int NOT NULL DEFAULT 3600 CHECK (interval_seconds BETWEEN 300 AND 86400),
    expected_cert_id uuid REFERENCES certificates (id) ON DELETE SET NULL,
    enabled          boolean NOT NULL DEFAULT true,
    state            text NOT NULL DEFAULT 'unknown' CHECK (state IN ('unknown', 'ok', 'mismatch', 'expiring', 'unreachable')),
    state_changed_at timestamptz NOT NULL DEFAULT now(),
    last_checked_at  timestamptz,
    next_check_at    timestamptz NOT NULL DEFAULT now(),
    last_fingerprint text NOT NULL DEFAULT '',
    last_not_after   timestamptz,
    last_issuer      text NOT NULL DEFAULT '' CHECK (length(last_issuer) <= 1000),
    last_error       text NOT NULL DEFAULT '' CHECK (length(last_error) <= 1000),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
-- ScanArgs (internal/monitor, every minute) only ever looks at enabled
-- monitors whose next check is due.
CREATE INDEX external_monitors_next_check ON external_monitors (next_check_at) WHERE enabled;

-- Pre-flight ruling: a restore (Task 10/11) loads tables under
-- SET CONSTRAINTS ALL DEFERRED because some reference each other
-- (Deviations R6 FK order, for example certificates.current_version_id), so
-- no fixed load order satisfies every foreign key at statement time. Every
-- non-river, non-goose foreign key becomes DEFERRABLE INITIALLY IMMEDIATE
-- here, once, for the whole schema (behaviour unchanged for every existing
-- caller: IMMEDIATE checking is still the default within a transaction that
-- never itself runs SET CONSTRAINTS). TestEveryForeignKeyDeferrable is the
-- standing test that keeps this true as later migrations add tables.
-- +goose StatementBegin
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.conname, c.conrelid::regclass::text AS tbl
        FROM pg_constraint c
        JOIN pg_namespace n ON n.oid = c.connamespace
        WHERE c.contype = 'f'
          AND n.nspname = 'public'
          AND c.conrelid::regclass::text NOT LIKE 'river_%'
          AND c.conrelid::regclass::text NOT LIKE 'goose_%'
    LOOP
        EXECUTE format('ALTER TABLE %s ALTER CONSTRAINT %I DEFERRABLE INITIALLY IMMEDIATE', r.tbl, r.conname);
    END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.conname, c.conrelid::regclass::text AS tbl
        FROM pg_constraint c
        JOIN pg_namespace n ON n.oid = c.connamespace
        WHERE c.contype = 'f'
          AND n.nspname = 'public'
          AND c.conrelid::regclass::text NOT LIKE 'river_%'
          AND c.conrelid::regclass::text NOT LIKE 'goose_%'
    LOOP
        EXECUTE format('ALTER TABLE %s ALTER CONSTRAINT %I NOT DEFERRABLE', r.tbl, r.conname);
    END LOOP;
END $$;
-- +goose StatementEnd

DROP TABLE external_monitors;
DROP TABLE notification_deliveries;
DROP TABLE notification_events;
DROP TABLE notification_channels;
