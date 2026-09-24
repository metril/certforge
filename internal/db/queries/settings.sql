-- name: GetSetting :one
SELECT * FROM settings WHERE key = $1;

-- name: UpsertSettingValue :exec
INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();

-- name: UpsertSettingSecret :exec
INSERT INTO settings (key, secret, updated_at) VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET secret = EXCLUDED.secret, updated_at = now();
