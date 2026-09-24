-- name: GetSetting :one
SELECT * FROM settings WHERE key = $1;

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
