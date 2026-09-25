-- +goose Up
-- "all" is the web UI's All orgs route (/o/all/...); reserve the slug so no
-- org can collide with it. Raise a clear, actionable error naming the org
-- first, instead of a bare constraint-violation, so an operator can rename
-- it before re-running the migration; the constraint below then always
-- validates immediately (no NOT VALID+VALIDATE split needed).
-- +goose StatementBegin
DO $$
DECLARE
    bad_id uuid;
BEGIN
    SELECT id INTO bad_id FROM orgs WHERE slug = 'all' LIMIT 1;
    IF bad_id IS NOT NULL THEN
        RAISE EXCEPTION 'org % has reserved slug "all"; rename it before this migration can run', bad_id;
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE orgs ADD CONSTRAINT orgs_slug_not_reserved CHECK (slug <> 'all');

-- +goose Down
ALTER TABLE orgs DROP CONSTRAINT orgs_slug_not_reserved;
