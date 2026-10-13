-- +goose Up
-- Hooks, server post actions and per-grant pfSense restarts become one
-- org-scoped library of actions. Grants carry an ordered steps list of
-- {"action": id} or {"group": id}. hook_runs keeps its name; hook_id now
-- points at actions.
ALTER TABLE hooks RENAME TO actions;
ALTER TABLE actions RENAME CONSTRAINT hooks_pkey TO actions_pkey;
ALTER TABLE actions RENAME CONSTRAINT hooks_org_id_fkey TO actions_org_id_fkey;
ALTER TABLE actions RENAME CONSTRAINT hooks_org_id_name_key TO actions_org_id_name_key;
ALTER TABLE actions RENAME CONSTRAINT hooks_name_check TO actions_name_check;
ALTER TABLE actions RENAME CONSTRAINT hooks_phase_check TO actions_phase_check;
ALTER TABLE actions RENAME CONSTRAINT hooks_timeout_seconds_check TO actions_timeout_seconds_check;

ALTER TABLE actions ADD COLUMN config jsonb NOT NULL DEFAULT '{}';
ALTER TABLE actions ADD COLUMN optional boolean NOT NULL DEFAULT false;
ALTER TABLE actions ADD COLUMN secret_cfg bytea;
UPDATE actions SET config = CASE kind
    WHEN 'exec' THEN jsonb_build_object('argv', to_jsonb(argv))
    ELSE jsonb_build_object('target', target) END;
ALTER TABLE actions DROP CONSTRAINT hooks_argv_check;
ALTER TABLE actions DROP COLUMN argv;
ALTER TABLE actions DROP COLUMN target;
ALTER TABLE actions DROP CONSTRAINT hooks_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check CHECK (kind IN (
    'exec', 'restart', 'ssh', 'pfsense_shell', 'pfsense_restart', 'truenas_restart',
    'routeros_restart', 'http', 'notify', 'verify_tls', 'wait'));

CREATE TABLE action_groups (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE,
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    action_ids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(action_ids) <= 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

ALTER TABLE client_cert_grants ADD COLUMN steps jsonb NOT NULL DEFAULT '[]';
CREATE INDEX client_cert_grants_steps_idx ON client_cert_grants USING gin (steps jsonb_path_ops);
UPDATE client_cert_grants g SET steps = COALESCE((
    SELECT jsonb_agg(jsonb_build_object('action', h.id) ORDER BY h.ord)
    FROM unnest(g.hook_ids) WITH ORDINALITY AS h(id, ord)), '[]'::jsonb)
WHERE cardinality(g.hook_ids) > 0;

-- +goose StatementBegin
DO $$
DECLARE
    r record;
    aid uuid;
    nm text;
    k text;
    tid text;
    tname text;
    torg uuid;
    ttype text;
BEGIN
    -- Post actions (also the legacy sshTargetId form; no kind means ssh).
    FOR r IN SELECT id, post_action, deploy_target_id FROM client_cert_grants
             WHERE post_action <> '{}'::jsonb AND post_action <> 'null'::jsonb
             ORDER BY created_at, id LOOP
        tid := COALESCE(r.post_action->>'targetId', r.post_action->>'sshTargetId');
        CONTINUE WHEN tid IS NULL;
        SELECT t.name, t.org_id INTO tname, torg FROM deploy_targets t WHERE t.id = tid::uuid;
        CONTINUE WHEN torg IS NULL;
        k := CASE WHEN r.post_action->>'kind' = 'pfsense' THEN 'pfsense_shell' ELSE 'ssh' END;
        nm := left(tname || ' post action', 100);
        aid := gen_random_uuid();
        IF EXISTS (SELECT 1 FROM actions WHERE org_id = torg AND name = nm) THEN
            nm := left(tname || ' post action', 100 - 9) || '-' || left(aid::text, 8);
        END IF;
        INSERT INTO actions (id, org_id, name, kind, phase, config, timeout_seconds)
        VALUES (aid, torg, nm, k, 'post_deploy',
                jsonb_build_object('targetId', tid, 'command', COALESCE(r.post_action->>'command', '')),
                LEAST(GREATEST(COALESCE((r.post_action->>'timeoutSeconds')::int, 60), 1), 3600));
        UPDATE client_cert_grants SET steps = steps || jsonb_build_array(jsonb_build_object('action', aid))
        WHERE id = r.id;
    END LOOP;

    -- Per-grant pfSense restart options.
    FOR r IN SELECT g.id, g.target_options, g.deploy_target_id, t.name AS tname, t.org_id AS torg
             FROM client_cert_grants g JOIN deploy_targets t ON t.id = g.deploy_target_id
             WHERE g.target_options ? 'pfsenseRestart'
             ORDER BY g.created_at, g.id LOOP
        aid := gen_random_uuid();
        nm := left(r.tname || ' restart services', 100);
        IF EXISTS (SELECT 1 FROM actions WHERE org_id = r.torg AND name = nm) THEN
            nm := left(r.tname || ' restart services', 100 - 9) || '-' || left(aid::text, 8);
        END IF;
        INSERT INTO actions (id, org_id, name, kind, phase, config, timeout_seconds)
        VALUES (aid, r.torg, nm, 'pfsense_restart', 'post_deploy',
                jsonb_build_object('targetId', r.deploy_target_id::text,
                    'mode', COALESCE(r.target_options->'pfsenseRestart'->>'mode', 'all'),
                    'services', COALESCE(r.target_options->'pfsenseRestart'->'services', '[]'::jsonb)),
                60);
        UPDATE client_cert_grants
        SET steps = steps || jsonb_build_array(jsonb_build_object('action', aid)),
            target_options = target_options - 'pfsenseRestart'
        WHERE id = r.id;
    END LOOP;
END $$;
-- +goose StatementEnd

ALTER TABLE client_cert_grants DROP COLUMN hook_ids;
ALTER TABLE client_cert_grants DROP COLUMN post_action;

-- +goose Down
ALTER TABLE client_cert_grants ADD COLUMN hook_ids uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE client_cert_grants ADD COLUMN post_action jsonb NOT NULL DEFAULT '{}';
UPDATE client_cert_grants g SET hook_ids = COALESCE((
    SELECT array_agg((s.step->>'action')::uuid ORDER BY s.ord)
    FROM jsonb_array_elements(g.steps) WITH ORDINALITY AS s(step, ord)
    JOIN actions a ON a.id = (s.step->>'action')::uuid AND a.kind IN ('exec', 'restart')), '{}');
UPDATE client_cert_grants g SET post_action = x.pa
FROM (
    SELECT DISTINCT ON (g2.id) g2.id,
           jsonb_build_object('kind', CASE a.kind WHEN 'pfsense_shell' THEN 'pfsense' ELSE 'ssh' END,
                              'targetId', a.config->>'targetId', 'command', a.config->>'command',
                              'timeoutSeconds', a.timeout_seconds) AS pa
    FROM client_cert_grants g2
    CROSS JOIN LATERAL jsonb_array_elements(g2.steps) WITH ORDINALITY AS s(step, ord)
    JOIN actions a ON a.id = (s.step->>'action')::uuid AND a.kind IN ('ssh', 'pfsense_shell') AND a.phase = 'post_deploy'
    ORDER BY g2.id, s.ord
) x
WHERE g.id = x.id AND g.client_id IS NULL;
UPDATE client_cert_grants g SET target_options = g.target_options || jsonb_build_object('pfsenseRestart',
    jsonb_build_object('mode', x.a_cfg->>'mode', 'services', COALESCE(x.a_cfg->'services', '[]'::jsonb)))
FROM (
    SELECT DISTINCT ON (g2.id) g2.id, a.config AS a_cfg
    FROM client_cert_grants g2
    CROSS JOIN LATERAL jsonb_array_elements(g2.steps) WITH ORDINALITY AS s(step, ord)
    JOIN actions a ON a.id = (s.step->>'action')::uuid AND a.kind = 'pfsense_restart'
    ORDER BY g2.id, s.ord
) x
WHERE g.id = x.id;
CREATE INDEX client_cert_grants_hook_ids_idx ON client_cert_grants USING gin (hook_ids);
ALTER TABLE client_cert_grants DROP COLUMN steps;
DROP TABLE action_groups;

DELETE FROM actions WHERE kind NOT IN ('exec', 'restart');
ALTER TABLE actions DROP CONSTRAINT actions_kind_check;
ALTER TABLE actions ADD COLUMN argv text[] NOT NULL DEFAULT '{}';
ALTER TABLE actions ADD COLUMN target text NOT NULL DEFAULT '';
UPDATE actions SET argv = COALESCE(ARRAY(SELECT jsonb_array_elements_text(config->'argv')), '{}'),
                   target = COALESCE(config->>'target', '');
ALTER TABLE actions ADD CONSTRAINT hooks_kind_check CHECK (kind IN ('exec', 'restart'));
ALTER TABLE actions ADD CONSTRAINT hooks_argv_check CHECK (
    (kind = 'exec' AND cardinality(argv) BETWEEN 1 AND 64)
    OR (kind = 'restart' AND cardinality(argv) = 0 AND target <> ''));
ALTER TABLE actions DROP COLUMN config;
ALTER TABLE actions DROP COLUMN optional;
ALTER TABLE actions DROP COLUMN secret_cfg;
ALTER TABLE actions RENAME CONSTRAINT actions_timeout_seconds_check TO hooks_timeout_seconds_check;
ALTER TABLE actions RENAME CONSTRAINT actions_phase_check TO hooks_phase_check;
ALTER TABLE actions RENAME CONSTRAINT actions_name_check TO hooks_name_check;
ALTER TABLE actions RENAME CONSTRAINT actions_org_id_name_key TO hooks_org_id_name_key;
ALTER TABLE actions RENAME CONSTRAINT actions_org_id_fkey TO hooks_org_id_fkey;
ALTER TABLE actions RENAME CONSTRAINT actions_pkey TO hooks_pkey;
ALTER TABLE actions RENAME TO hooks;
