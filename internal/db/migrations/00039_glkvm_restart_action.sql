-- +goose Up
ALTER TABLE actions DROP CONSTRAINT IF EXISTS actions_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check CHECK (kind IN (
    'exec', 'restart', 'ssh', 'pfsense_shell', 'pfsense_restart', 'pikvm_restart', 'glkvm_restart', 'truenas_restart',
    'routeros_restart', 'http', 'notify', 'verify_tls', 'wait'));

-- +goose Down
-- The narrower check rejects the new kind, so drop those actions and the
-- steps and groups that reference them first.
UPDATE client_cert_grants g SET steps = COALESCE((
    SELECT jsonb_agg(s ORDER BY o)
    FROM jsonb_array_elements(g.steps) WITH ORDINALITY AS e(s, o)
    WHERE NOT (s ? 'action' AND (s->>'action')::uuid IN (SELECT id FROM actions WHERE kind = 'glkvm_restart'))), '[]'::jsonb)
WHERE g.steps <> '[]'::jsonb;
UPDATE action_groups SET action_ids = ARRAY(
    SELECT x FROM unnest(action_ids) WITH ORDINALITY AS u(x, o)
    WHERE x NOT IN (SELECT id FROM actions WHERE kind = 'glkvm_restart') ORDER BY o)
WHERE action_ids && ARRAY(SELECT id FROM actions WHERE kind = 'glkvm_restart');
DELETE FROM actions WHERE kind = 'glkvm_restart';
ALTER TABLE actions DROP CONSTRAINT IF EXISTS actions_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check CHECK (kind IN (
    'exec', 'restart', 'ssh', 'pfsense_shell', 'pfsense_restart', 'pikvm_restart', 'truenas_restart',
    'routeros_restart', 'http', 'notify', 'verify_tls', 'wait'));
