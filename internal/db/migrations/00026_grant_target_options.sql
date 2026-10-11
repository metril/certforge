-- +goose Up
-- Per-grant target options (e.g. Traefik defaultCert). A target-level
-- defaultCert is moved onto every grant that references the target.
ALTER TABLE client_cert_grants ADD COLUMN target_options jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE client_cert_grants g SET target_options = '{"defaultCert":true}'::jsonb
FROM deploy_targets t
WHERE t.id = g.deploy_target_id AND t.type = 'traefik' AND t.config->>'defaultCert' = 'true';

UPDATE deploy_targets SET config = config - 'defaultCert' WHERE type = 'traefik' AND config ? 'defaultCert';

-- +goose Down
-- The target-level defaultCert is not restored.
ALTER TABLE client_cert_grants DROP COLUMN target_options;
