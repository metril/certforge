-- +goose Up
-- Phase 5A: private CA kinds (localca, vaultpki) alongside acme, server-run
-- deploy targets (vault-kv), and client-less "server grants" that deploy
-- straight to a deploy target with no agent/client involved.

-- type widens from acme-only to the three CA kinds a signer can back
-- (Deviations R4 key types, R9 CA path). config holds each kind's public
-- config (issuance.CA.Config); secret_cfg is a marshalled crypto.Blob for
-- write-only fields such as localca's imported private key. not_before/
-- not_after cache the issuing certificate's (localca) or Vault CA's
-- (vaultpki) validity window; both stay NULL for acme. crl_number is the
-- next CRL sequence number for a localca CA (Deviations R4 CRL after
-- rotation).
ALTER TABLE cas DROP CONSTRAINT cas_type_check;
ALTER TABLE cas ADD CONSTRAINT cas_type_check CHECK (type IN ('acme', 'localca', 'vaultpki'));
ALTER TABLE cas
    ADD COLUMN config     jsonb NOT NULL DEFAULT '{}',
    ADD COLUMN secret_cfg bytea,
    ADD COLUMN not_before timestamptz,
    ADD COLUMN not_after  timestamptz,
    ADD COLUMN crl_number bigint NOT NULL DEFAULT 0;
-- preset/directory_url stay NOT NULL (never actually needed for a private
-- CA; the application writes '' for those) but are only required to be
-- non-empty for an acme CA.
ALTER TABLE cas ADD CONSTRAINT cas_acme_requires_preset_directory
    CHECK (type <> 'acme' OR (preset <> '' AND directory_url <> ''));

-- deploy_targets gains vault-kv, a server-run target type (Deviations R9);
-- runs_on gains server, and a target's runs_on must match its type.
ALTER TABLE deploy_targets DROP CONSTRAINT deploy_targets_type_check;
ALTER TABLE deploy_targets ADD CONSTRAINT deploy_targets_type_check CHECK (type IN ('traefik', 'vault-kv'));
ALTER TABLE deploy_targets DROP CONSTRAINT deploy_targets_runs_on_check;
ALTER TABLE deploy_targets ADD CONSTRAINT deploy_targets_runs_on_check CHECK (runs_on IN ('agent', 'server'));
ALTER TABLE deploy_targets ADD CONSTRAINT deploy_targets_type_runs_on_check
    CHECK ((type = 'vault-kv') = (runs_on = 'server'));

-- A "server grant" (Deviations R9/R6 grant paths, client-less grants) has no
-- client: it deploys a certificate straight to a server-run deploy target.
-- client_id becomes optional, but a grant must still have a client or a
-- target, and only one live server grant may exist per (target, cert) pair
-- (client grants already have this via client_cert_grants_live).
ALTER TABLE client_cert_grants ALTER COLUMN client_id DROP NOT NULL;
ALTER TABLE client_cert_grants ADD CONSTRAINT client_cert_grants_client_or_target
    CHECK (client_id IS NOT NULL OR deploy_target_id IS NOT NULL);
CREATE UNIQUE INDEX client_cert_grants_server_live ON client_cert_grants (deploy_target_id, cert_id)
    WHERE client_id IS NULL AND removed_at IS NULL;

-- server_deployments tracks a server grant's own deploy state (there is no
-- agent to report installed files back), the way deployments/agent reports
-- do for an agent-run grant.
CREATE TABLE server_deployments (
    grant_id     uuid PRIMARY KEY REFERENCES client_cert_grants (id) ON DELETE CASCADE,
    version_id   uuid REFERENCES certificate_versions (id) ON DELETE SET NULL,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'deployed', 'failed')),
    last_error   text NOT NULL DEFAULT '',
    deployed_at  timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE server_deployments;

DROP INDEX client_cert_grants_server_live;
-- A server grant has no client to fall back to, so it cannot survive
-- client_id becoming required again.
DELETE FROM client_cert_grants WHERE client_id IS NULL;
ALTER TABLE client_cert_grants DROP CONSTRAINT client_cert_grants_client_or_target;
ALTER TABLE client_cert_grants ALTER COLUMN client_id SET NOT NULL;

-- A server-run target has no meaning once runs_on is agent-only again.
DELETE FROM deploy_targets WHERE runs_on = 'server';
ALTER TABLE deploy_targets DROP CONSTRAINT deploy_targets_type_runs_on_check;
ALTER TABLE deploy_targets DROP CONSTRAINT deploy_targets_runs_on_check;
ALTER TABLE deploy_targets ADD CONSTRAINT deploy_targets_runs_on_check CHECK (runs_on IN ('agent'));
ALTER TABLE deploy_targets DROP CONSTRAINT deploy_targets_type_check;
ALTER TABLE deploy_targets ADD CONSTRAINT deploy_targets_type_check CHECK (type IN ('traefik'));

-- A private CA has no meaning once type is acme-only again.
DELETE FROM cas WHERE type <> 'acme';
ALTER TABLE cas DROP CONSTRAINT cas_acme_requires_preset_directory;
ALTER TABLE cas
    DROP COLUMN crl_number,
    DROP COLUMN not_after,
    DROP COLUMN not_before,
    DROP COLUMN secret_cfg,
    DROP COLUMN config;
ALTER TABLE cas DROP CONSTRAINT cas_type_check;
ALTER TABLE cas ADD CONSTRAINT cas_type_check CHECK (type IN ('acme'));
