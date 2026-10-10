-- +goose Up
-- Token proof of possession: the agent names its token by lookup_id =
-- sha256("cf-enrol-id" || token_hash) and proves it holds the secret with an
-- HMAC keyed by token_hash, so neither the token nor its hash ever travels.
ALTER TABLE enrollment_tokens ADD COLUMN lookup_id bytea;
UPDATE enrollment_tokens SET lookup_id = sha256(convert_to('cf-enrol-id', 'UTF8') || token_hash);
ALTER TABLE enrollment_tokens ALTER COLUMN lookup_id SET NOT NULL;
CREATE UNIQUE INDEX enrollment_tokens_lookup ON enrollment_tokens (lookup_id);

-- A backup written before this migration has no lookup_id in its
-- enrollment_tokens rows; restore loads at version 24, so derive the value
-- (same formula as agentproto.LookupIDBytes) when an insert omits it.
-- +goose StatementBegin
CREATE FUNCTION enrollment_tokens_lookup_default() RETURNS trigger AS $$
BEGIN
    IF NEW.lookup_id IS NULL THEN
        NEW.lookup_id := sha256(convert_to('cf-enrol-id', 'UTF8') || NEW.token_hash);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER enrollment_tokens_lookup_default BEFORE INSERT ON enrollment_tokens
    FOR EACH ROW EXECUTE FUNCTION enrollment_tokens_lookup_default();

-- One row per redeemed token: the CSR waits here for an admin (status
-- pending) until approved, then the agent collects its certificate by polling
-- (issued). expires_at is the approval deadline while pending and the
-- collection deadline once approved. poll_secret_hash is sha256 of the secret
-- only the agent holds; the agent also signs each poll with the CSR key.
CREATE TABLE enrollment_requests (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE,
    client_id        uuid NOT NULL REFERENCES clients (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE,
    token_id         uuid NOT NULL UNIQUE REFERENCES enrollment_tokens (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE,
    poll_secret_hash bytea NOT NULL,
    csr              text NOT NULL,
    pubkey_fp        text NOT NULL,
    verify_code      text NOT NULL,
    facts            jsonb NOT NULL DEFAULT '{}',
    source_ip        text NOT NULL DEFAULT '',
    status           text NOT NULL CHECK (status IN ('pending', 'approved', 'issued', 'rejected', 'expired')),
    certificate_pem  text,
    decided_by       text NOT NULL DEFAULT '',
    decided_at       timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL
);
CREATE INDEX enrollment_requests_org_status ON enrollment_requests (org_id, status, expires_at);
CREATE INDEX enrollment_requests_client ON enrollment_requests (client_id);

ALTER TABLE notification_events DROP CONSTRAINT notification_events_kind_check;
ALTER TABLE notification_events ADD CONSTRAINT notification_events_kind_check CHECK (kind IN (
    'cert.issued', 'cert.renewal_failed', 'cert.expiring', 'cert.expired',
    'deploy.failed', 'deploy.drift', 'client.offline', 'agent.cert_expiring', 'client.pending_approval',
    'monitor.mismatch', 'monitor.unreachable', 'monitor.expiring', 'monitor.recovered',
    'backup.completed', 'backup.failed', 'test'
));

-- +goose Down
ALTER TABLE notification_events DROP CONSTRAINT notification_events_kind_check;
DELETE FROM notification_events WHERE kind = 'client.pending_approval';
ALTER TABLE notification_events ADD CONSTRAINT notification_events_kind_check CHECK (kind IN (
    'cert.issued', 'cert.renewal_failed', 'cert.expiring', 'cert.expired',
    'deploy.failed', 'deploy.drift', 'client.offline', 'agent.cert_expiring',
    'monitor.mismatch', 'monitor.unreachable', 'monitor.expiring', 'monitor.recovered',
    'backup.completed', 'backup.failed', 'test'
));
DROP TABLE enrollment_requests;
DROP TRIGGER enrollment_tokens_lookup_default ON enrollment_tokens;
DROP FUNCTION enrollment_tokens_lookup_default();
DROP INDEX enrollment_tokens_lookup;
ALTER TABLE enrollment_tokens DROP COLUMN lookup_id;
