-- name: GetSetting :one
SELECT * FROM settings WHERE key = $1;

-- name: GetSettingForUpdate :one
-- Row-locks the setting so a read-modify-write (PutSectionTx) serializes
-- with a concurrent PUT of the same section.
SELECT * FROM settings WHERE key = $1 FOR UPDATE;

-- name: UpsertSettingValue :exec
INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();

-- name: UpsertSettingSecret :exec
INSERT INTO settings (key, secret, updated_at) VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET secret = EXCLUDED.secret, updated_at = now();

-- name: InsertSettingSecretIfAbsent :execrows
-- Insert-or-fill: creates the row if it doesn't exist, or fills in the
-- secret if the row exists but its secret is still NULL. A row whose
-- secret is already set is left untouched (0 rows affected).
INSERT INTO settings (key, secret, updated_at) VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET secret = EXCLUDED.secret, updated_at = now()
WHERE settings.secret IS NULL;

-- name: MergeSettingValue :exec
-- Atomic partial update of a JSON *object* value (final review fix wave,
-- finding 2): patch's own top-level keys overwrite, every other key already
-- stored is kept, in one statement — unlike Get-then-Set (read, mutate a
-- few fields in Go, write the whole struct back), which loses a concurrent
-- writer's own change to any field the reader didn't itself touch whenever
-- the two overlap (backup.Service's own on-demand vs. scheduled status
-- writes, service.go:118/schedule.go:68). jsonb_typeof guards a row whose
-- stored value isn't an object yet (never written, or still the column's
-- 'null'::jsonb default) so `||` (object-concatenation; undefined between
-- two non-objects) has an object on both sides.
INSERT INTO settings (key, value, updated_at) VALUES (sqlc.arg(key), sqlc.arg(patch), now())
ON CONFLICT (key) DO UPDATE SET
    value = (CASE WHEN jsonb_typeof(settings.value) = 'object' THEN settings.value ELSE '{}'::jsonb END) || EXCLUDED.value,
    updated_at = now();
