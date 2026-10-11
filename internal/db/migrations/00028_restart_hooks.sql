-- +goose Up
-- A restart hook restarts a Docker container or systemd unit by name instead
-- of running an argv; its argv is empty and target names what to restart.
ALTER TABLE hooks DROP CONSTRAINT hooks_argv_check;
ALTER TABLE hooks ADD COLUMN kind text NOT NULL DEFAULT 'exec' CHECK (kind IN ('exec', 'restart'));
ALTER TABLE hooks ADD COLUMN target text NOT NULL DEFAULT '';
ALTER TABLE hooks ADD CONSTRAINT hooks_argv_check CHECK (
    (kind = 'exec' AND cardinality(argv) BETWEEN 1 AND 64)
    OR (kind = 'restart' AND cardinality(argv) = 0 AND target <> ''));

-- +goose Down
DELETE FROM hooks WHERE kind = 'restart';
ALTER TABLE hooks DROP CONSTRAINT hooks_argv_check;
ALTER TABLE hooks DROP COLUMN target;
ALTER TABLE hooks DROP COLUMN kind;
ALTER TABLE hooks ADD CONSTRAINT hooks_argv_check CHECK (cardinality(argv) BETWEEN 1 AND 64);
