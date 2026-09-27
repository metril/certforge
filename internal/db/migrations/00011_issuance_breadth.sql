-- +goose Up
-- Phase 4A: unmanaged (imported/uploaded) certificates, keyless versions,
-- password-protected/multi-cert layouts, extra deployed versions, and a
-- local ledger of the CA's own ACME rate limits.

-- managed=false marks a certificate CertForge tracks but does not renew
-- (imported or uploaded); such a certificate must have no next_renew_at.
-- The ari_window_* columns cache the CA's ACME Renewal Information window;
-- ari_retry_after is the earliest time the next poll may run.
ALTER TABLE certificates
    ADD COLUMN managed          boolean NOT NULL DEFAULT true,
    ADD COLUMN ari_window_start timestamptz,
    ADD COLUMN ari_window_end   timestamptz,
    ADD COLUMN ari_checked_at   timestamptz,
    ADD COLUMN ari_retry_after  timestamptz,
    ADD CONSTRAINT certificates_unmanaged_no_renewal CHECK (managed OR next_renew_at IS NULL);

-- private_key becomes nullable so a keyless upload/import can be stored;
-- ca_id (nullable: certificates has no ca_id column, the CA lives in
-- overrides jsonb) is the CA this version was actually issued/imported
-- against, used by the rate ledger.
ALTER TABLE certificate_versions
    ALTER COLUMN private_key DROP NOT NULL,
    ADD COLUMN ca_id uuid REFERENCES cas(id) ON DELETE SET NULL;

-- password is a marshalled crypto.Blob sealing a P12/JKS layout's export
-- password (NULL = none, or the layout has no p12/jks file); extra_cert_ids
-- are additional certificates a layout bundles alongside its own (rendered
-- as OutputPart "extra").
ALTER TABLE output_specs
    ADD COLUMN password       bytea,
    ADD COLUMN extra_cert_ids uuid[] NOT NULL DEFAULT '{}';

-- extra_version_ids records which version of each extra certificate a
-- deployment last rendered, alongside its own version_id, for drift
-- comparison the same way version_id already works.
ALTER TABLE deployments
    ADD COLUMN extra_version_ids uuid[] NOT NULL DEFAULT '{}';

-- A local record of the CA's own ACME rate limits (new_order, cert_issued,
-- failed_validation), so issuance can refuse an order locally before the CA
-- rejects it. registered_domain/names_hash/cert_id are populated per kind:
-- new_order rows key on ca_id alone (registered_domain/names_hash empty),
-- cert_issued rows carry names_hash (and cert_id) for the duplicate-cert
-- limit, failed_validation rows carry registered_domain.
CREATE TABLE rate_ledger (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id             uuid NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
    kind              text NOT NULL CHECK (kind IN ('new_order', 'cert_issued', 'failed_validation')),
    registered_domain text NOT NULL DEFAULT '',
    names_hash        text NOT NULL DEFAULT '',
    cert_id           uuid REFERENCES certificates(id) ON DELETE SET NULL,
    at                timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX rate_ledger_ca_kind_domain_idx ON rate_ledger (ca_id, kind, registered_domain, at);
CREATE INDEX rate_ledger_ca_names_hash_idx ON rate_ledger (ca_id, names_hash, at) WHERE kind = 'cert_issued';
CREATE INDEX rate_ledger_at_idx ON rate_ledger (at);

-- +goose Down
DROP TABLE rate_ledger;

ALTER TABLE deployments
    DROP COLUMN extra_version_ids;

ALTER TABLE output_specs
    DROP COLUMN extra_cert_ids,
    DROP COLUMN password;

ALTER TABLE certificate_versions
    DROP COLUMN ca_id,
    ALTER COLUMN private_key SET NOT NULL;

ALTER TABLE certificates
    DROP CONSTRAINT certificates_unmanaged_no_renewal,
    DROP COLUMN ari_retry_after,
    DROP COLUMN ari_checked_at,
    DROP COLUMN ari_window_end,
    DROP COLUMN ari_window_start,
    DROP COLUMN managed;
