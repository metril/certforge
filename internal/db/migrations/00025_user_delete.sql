-- +goose Up
-- Hard user deletion: an API key outlives its creator as an orphan (revoked
-- by the delete handler), so created_by becomes nullable and nulls on delete.
ALTER TABLE api_keys ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE api_keys DROP CONSTRAINT api_keys_created_by_fkey;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL;

-- +goose Down
-- Orphaned keys have no creator to restore; drop them.
DELETE FROM api_keys WHERE created_by IS NULL;
ALTER TABLE api_keys DROP CONSTRAINT api_keys_created_by_fkey;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users (id);
ALTER TABLE api_keys ALTER COLUMN created_by SET NOT NULL;
