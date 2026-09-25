-- +goose Up
-- The client's desired_revision at the moment a grant was marked removed:
-- an agent's removal confirmation only counts when it reports from that
-- revision or later, so a deploy result for assignments fetched before the
-- delete cannot confirm a removal it never saw.
ALTER TABLE client_cert_grants ADD COLUMN removed_revision bigint NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE client_cert_grants DROP COLUMN removed_revision;
