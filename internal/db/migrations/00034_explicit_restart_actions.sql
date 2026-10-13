-- +goose Up
-- Restarts are explicit actions, never bundled into a deploy. PiKVM and
-- pfSense deploys no longer restart anything, so every grant that relied on
-- the built-in restart gets an explicit restart step.
ALTER TABLE actions DROP CONSTRAINT IF EXISTS actions_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check CHECK (kind IN (
    'exec', 'restart', 'ssh', 'pfsense_shell', 'pfsense_restart', 'pikvm_restart', 'truenas_restart',
    'routeros_restart', 'http', 'notify', 'verify_tls', 'wait'));

-- +goose StatementBegin
DO $$
DECLARE
    t record;
    aid uuid;
    nm text;
    pfx text;
BEGIN
    -- PiKVM: one kvmd-nginx restart action per target with a grant lacking one.
    FOR t IN SELECT id, org_id, name FROM deploy_targets WHERE type = 'pikvm' ORDER BY created_at, id LOOP
        CONTINUE WHEN NOT EXISTS (
            SELECT 1 FROM client_cert_grants g WHERE g.deploy_target_id = t.id AND g.client_id IS NULL
              AND NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements(g.steps) s
                JOIN actions a ON a.kind = 'pikvm_restart' AND a.config->>'targetId' = t.id::text
                WHERE a.id = (s->>'action')::uuid));
        aid := gen_random_uuid();
        pfx := 'Restart kvmd-nginx · ';
        nm := left(pfx || t.name, 100);
        IF EXISTS (SELECT 1 FROM actions WHERE org_id = t.org_id AND name = nm) THEN
            nm := left(pfx || t.name, 100 - 9) || '-' || left(aid::text, 8);
        END IF;
        INSERT INTO actions (id, org_id, name, kind, phase, config, timeout_seconds)
        VALUES (aid, t.org_id, nm, 'pikvm_restart', 'post_deploy',
                jsonb_build_object('targetId', t.id::text, 'service', 'kvmd-nginx'), 60);
        UPDATE client_cert_grants g
        SET steps = g.steps || jsonb_build_array(jsonb_build_object('action', aid))
        WHERE g.deploy_target_id = t.id AND g.client_id IS NULL
          AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(g.steps) s
            JOIN actions a ON a.kind = 'pikvm_restart' AND a.config->>'targetId' = t.id::text
            WHERE a.id = (s->>'action')::uuid AND a.id <> aid);
    END LOOP;

    -- pfSense: the target default restartServices (true or absent) becomes a step.
    FOR t IN SELECT id, org_id, name FROM deploy_targets
             WHERE type = 'pfsense' AND COALESCE((config->>'restartServices')::boolean, true)
             ORDER BY created_at, id LOOP
        CONTINUE WHEN NOT EXISTS (
            SELECT 1 FROM client_cert_grants g WHERE g.deploy_target_id = t.id AND g.client_id IS NULL
              AND NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements(g.steps) s
                JOIN actions a ON a.kind = 'pfsense_restart' AND a.config->>'targetId' = t.id::text
                WHERE a.id = (s->>'action')::uuid));
        aid := gen_random_uuid();
        pfx := 'Restart pfSense services · ';
        nm := left(pfx || t.name, 100);
        IF EXISTS (SELECT 1 FROM actions WHERE org_id = t.org_id AND name = nm) THEN
            nm := left(pfx || t.name, 100 - 9) || '-' || left(aid::text, 8);
        END IF;
        INSERT INTO actions (id, org_id, name, kind, phase, config, timeout_seconds)
        VALUES (aid, t.org_id, nm, 'pfsense_restart', 'post_deploy',
                jsonb_build_object('targetId', t.id::text, 'mode', 'all'), 60);
        UPDATE client_cert_grants g
        SET steps = g.steps || jsonb_build_array(jsonb_build_object('action', aid))
        WHERE g.deploy_target_id = t.id AND g.client_id IS NULL
          AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(g.steps) s
            JOIN actions a ON a.kind = 'pfsense_restart' AND a.config->>'targetId' = t.id::text
            WHERE a.id = (s->>'action')::uuid AND a.id <> aid);
    END LOOP;
END $$;
-- +goose StatementEnd

UPDATE deploy_targets SET config = config - 'restartServices' WHERE type = 'pfsense' AND config ? 'restartServices';

-- +goose Down
UPDATE deploy_targets SET config = config || '{"restartServices": true}'::jsonb WHERE type = 'pfsense';

-- Drop the created restart steps, then every pikvm_restart action (the old
-- kind check rejects the kind).
UPDATE client_cert_grants g SET steps = COALESCE((
    SELECT jsonb_agg(s ORDER BY o)
    FROM jsonb_array_elements(g.steps) WITH ORDINALITY AS e(s, o)
    WHERE NOT (s ? 'action' AND (s->>'action')::uuid IN (
        SELECT id FROM actions
        WHERE kind = 'pikvm_restart' OR (kind = 'pfsense_restart' AND name LIKE 'Restart pfSense services · %')))), '[]'::jsonb)
WHERE g.steps <> '[]'::jsonb;
UPDATE action_groups SET action_ids = ARRAY(
    SELECT x FROM unnest(action_ids) WITH ORDINALITY AS u(x, o)
    WHERE x NOT IN (SELECT id FROM actions WHERE kind = 'pikvm_restart') ORDER BY o)
WHERE action_ids && ARRAY(SELECT id FROM actions WHERE kind = 'pikvm_restart');
DELETE FROM actions WHERE kind = 'pikvm_restart'
   OR (kind = 'pfsense_restart' AND name LIKE 'Restart pfSense services · %');

ALTER TABLE actions DROP CONSTRAINT IF EXISTS actions_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check CHECK (kind IN (
    'exec', 'restart', 'ssh', 'pfsense_shell', 'pfsense_restart', 'truenas_restart',
    'routeros_restart', 'http', 'notify', 'verify_tls', 'wait'));
