-- +goose Up
-- Device actions no longer name a target: they run against the deploy target
-- of the server grant that uses them. A step whose action named another
-- target (or a grant without one) is removed and recorded; the server
-- audits and clears the records at startup.
CREATE TABLE IF NOT EXISTS migrated_step_removals (
    grant_id      uuid        NOT NULL,
    action_id     uuid        NOT NULL,
    old_target_id uuid,
    reason        text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- +goose StatementBegin
DO $$
DECLARE
    device text[] := ARRAY['ssh', 'pfsense_shell', 'pfsense_restart', 'pikvm_restart', 'glkvm_restart', 'truenas_restart', 'routeros_restart'];
    g record;
    s record;
    m record;
    out_steps jsonb;
    ids uuid[];
    hit boolean;
BEGIN
    FOR g IN SELECT id, deploy_target_id, steps FROM client_cert_grants
             WHERE deploy_target_id IS NOT NULL AND jsonb_typeof(steps) = 'array' AND steps <> '[]'::jsonb LOOP
        out_steps := '[]'::jsonb;
        FOR s IN SELECT e.v, e.o FROM jsonb_array_elements(g.steps) WITH ORDINALITY AS e(v, o) ORDER BY e.o LOOP
            IF s.v ? 'action' THEN
                ids := ARRAY[(s.v->>'action')::uuid];
            ELSIF s.v ? 'group' THEN
                SELECT action_ids INTO ids FROM action_groups WHERE id = (s.v->>'group')::uuid;
                ids := COALESCE(ids, ARRAY[]::uuid[]);
            ELSE
                out_steps := out_steps || jsonb_build_array(s.v);
                CONTINUE;
            END IF;
            -- Mismatched members of this step.
            hit := false;
            FOR m IN SELECT x AS id FROM unnest(ids) AS x
                     WHERE EXISTS (SELECT 1 FROM actions a WHERE a.id = x AND a.kind = ANY (device) AND a.config ? 'targetId'
                                   AND a.config->>'targetId' IS DISTINCT FROM g.deploy_target_id::text) LOOP
                hit := true;
            END LOOP;
            IF NOT hit THEN
                out_steps := out_steps || jsonb_build_array(s.v);
                CONTINUE;
            END IF;
            -- Inline a group (a direct action is its own single member).
            FOR m IN SELECT x.id, x.o FROM unnest(ids) WITH ORDINALITY AS x(id, o) ORDER BY x.o LOOP
                IF EXISTS (SELECT 1 FROM actions a WHERE a.id = m.id AND a.kind = ANY (device) AND a.config ? 'targetId'
                           AND a.config->>'targetId' IS DISTINCT FROM g.deploy_target_id::text) THEN
                    INSERT INTO migrated_step_removals (grant_id, action_id, old_target_id, reason)
                    SELECT g.id, a.id,
                           CASE WHEN a.config->>'targetId' ~ '^[0-9a-fA-F-]{36}$' THEN (a.config->>'targetId')::uuid END,
                           'target_mismatch'
                    FROM actions a WHERE a.id = m.id;
                ELSE
                    out_steps := out_steps || jsonb_build_array(jsonb_build_object('action', m.id));
                END IF;
            END LOOP;
        END LOOP;
        IF out_steps <> g.steps THEN
            UPDATE client_cert_grants SET steps = out_steps WHERE id = g.id;
        END IF;
    END LOOP;
END $$;
-- +goose StatementEnd

UPDATE actions SET config = config - 'targetId'
WHERE config ? 'targetId'
  AND kind IN ('ssh', 'pfsense_shell', 'pfsense_restart', 'pikvm_restart', 'glkvm_restart', 'truenas_restart', 'routeros_restart');

-- +goose Down
-- Irreversible: the removed steps and stripped targetId values are not restored.
SELECT 1;
