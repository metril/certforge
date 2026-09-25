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
-- those three columns, and only ever landing on hash_alg = 'hmac-sha256' —
-- it can rewrite a row's algorithm forward, from sha256 to hmac-sha256,
-- never back; every other column, and DELETE/TRUNCATE, stay append-only
-- exactly as before. This is a defense-in-depth backstop, not a proof of
-- integrity by itself: it stops a relabel-only downgrade via UPDATE, but an
-- UPDATE that keeps hash_alg = 'hmac-sha256' while writing a wrong hash is
-- still allowed here and is only caught by Check verifying it with the real
-- key (fix round 1, item 2; see ADR 0008).
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
        AND NEW.ip = OLD.ip AND NEW.details = OLD.details
        AND NEW.hash_alg = 'hmac-sha256' THEN
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
