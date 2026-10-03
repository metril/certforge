-- +goose Up
-- sessions.user_id is a foreign key with ON DELETE CASCADE (and the target of
-- per-user session revocation), so deleting or deactivating a user otherwise
-- scans every session.
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

-- The "which layouts bundle this certificate / which grants use this hook"
-- lookups are array-containment predicates (col @> ARRAY[id]); a GIN index
-- serves them, where the old = ANY(col) form could not use one.
CREATE INDEX output_specs_extra_cert_ids_idx ON output_specs USING gin (extra_cert_ids);
CREATE INDEX client_cert_grants_hook_ids_idx ON client_cert_grants USING gin (hook_ids);

-- The NAMES of the fields held in secret_cfg, kept in plaintext so listing
-- DNS credentials does not have to decrypt every row. Never values. Rows
-- written before this migration keep an empty array and are read by opening
-- secret_cfg until their next write (same scheme as migration 00017).
ALTER TABLE dns_provider_credentials ADD COLUMN stored_secret_keys text[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE dns_provider_credentials DROP COLUMN stored_secret_keys;
DROP INDEX client_cert_grants_hook_ids_idx;
DROP INDEX output_specs_extra_cert_ids_idx;
DROP INDEX sessions_user_id_idx;
