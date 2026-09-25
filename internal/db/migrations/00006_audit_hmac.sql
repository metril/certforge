-- +goose Up
-- Existing rows keep their plain SHA-256 links until serve re-chains them
-- with HMAC-SHA256 (audit.Rechain, ADR 0008). Adding a column with a
-- constant default rewrites no rows and fires no row triggers.
ALTER TABLE audit_events ADD COLUMN hash_alg text NOT NULL DEFAULT 'sha256'
    CHECK (hash_alg IN ('sha256', 'hmac-sha256'));

-- audit.Rechain (ADR 0008) needs to rewrite prev_hash, hash and hash_alg on
-- existing rows, under the audit advisory lock, without disabling the
-- append-only trigger (that needs table ownership, which the app role does
-- not have). Instead the trigger itself allows an UPDATE that changes only
-- those three columns; every other column, and DELETE/TRUNCATE, stay
-- append-only exactly as before.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_events_block_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
        AND NEW.id = OLD.id AND NEW.ts = OLD.ts
        AND NEW.actor_type = OLD.actor_type AND NEW.actor_id = OLD.actor_id
        AND NEW.action = OLD.action AND NEW.resource_type = OLD.resource_type
        AND NEW.resource_id = OLD.resource_id
        AND NEW.org_id IS NOT DISTINCT FROM OLD.org_id
        AND NEW.ip = OLD.ip AND NEW.details = OLD.details THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_events_block_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;
-- +goose StatementEnd

ALTER TABLE audit_events DROP COLUMN hash_alg;
