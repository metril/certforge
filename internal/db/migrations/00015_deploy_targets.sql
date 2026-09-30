-- +goose Up
-- Phase 7A Task 1: deploy_targets grows a secret_cfg column (a marshalled
-- crypto.Blob, the same convention as cas.secret_cfg and
-- dns_provider_credentials.secret_cfg) for target types with write-only
-- secret fields (Deviations R2, R10). type/runs_on agreement moves out of
-- the database: the registry (internal/targets), not a fixed CHECK, is now
-- authoritative for which type codes exist and which runs_on each one
-- requires (Deviations R16) — validTarget in Go replaces both dropped
-- constraints. The runs_on IN ('agent', 'server') check stays: that rule
-- is unrelated to the registry and still holds for every type.
ALTER TABLE deploy_targets DROP CONSTRAINT deploy_targets_type_runs_on_check;
ALTER TABLE deploy_targets DROP CONSTRAINT deploy_targets_type_check;
ALTER TABLE deploy_targets ADD COLUMN secret_cfg bytea;

-- +goose Down
-- The registry may have accepted types/runs_on combinations the old fixed
-- checks never allowed (anything beyond traefik/vault-kv); such rows
-- cannot satisfy the restored constraints, so they are deleted first, the
-- same way earlier migrations clear out rows a narrower Down cannot keep
-- (00012's own Down on deploy_targets).
DELETE FROM deploy_targets WHERE type NOT IN ('traefik', 'vault-kv');
ALTER TABLE deploy_targets DROP COLUMN secret_cfg;
ALTER TABLE deploy_targets ADD CONSTRAINT deploy_targets_type_check CHECK (type IN ('traefik', 'vault-kv'));
ALTER TABLE deploy_targets ADD CONSTRAINT deploy_targets_type_runs_on_check
    CHECK ((type = 'vault-kv') = (runs_on = 'server'));
