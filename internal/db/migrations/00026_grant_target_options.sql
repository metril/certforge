-- +goose Up
-- Per-grant target options (e.g. Traefik defaultCert). A target-level
-- defaultCert is moved onto one live grant per client: the certificate whose
-- name sorts first, which is the one Traefik's file provider served.
ALTER TABLE client_cert_grants ADD COLUMN target_options jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE client_cert_grants g SET target_options = '{"defaultCert":true}'::jsonb
FROM (
    SELECT DISTINCT ON (g2.client_id, g2.deploy_target_id) g2.id
    FROM client_cert_grants g2
    JOIN deploy_targets t ON t.id = g2.deploy_target_id
    JOIN certificates c ON c.id = g2.cert_id
    WHERE g2.removed_at IS NULL AND t.type = 'traefik' AND t.config->>'defaultCert' = 'true'
    ORDER BY g2.client_id, g2.deploy_target_id, lower(c.name), c.name, g2.id
) pick
WHERE g.id = pick.id;

UPDATE deploy_targets SET config = config - 'defaultCert' WHERE type = 'traefik' AND config ? 'defaultCert';

-- +goose Down
-- The target-level defaultCert is not restored.
ALTER TABLE client_cert_grants DROP COLUMN target_options;
