-- +goose Up
-- A server grant whose post steps end in batchable ones (restarts, waits) parks
-- the rest here after its deploy, so the post-batch job can run identical steps
-- once for all grants on the same target. Deleted when the tail finishes, or
-- when the grant is re-armed (deploy_seq moves on).
CREATE TABLE server_post_tails (
    grant_id         uuid        PRIMARY KEY REFERENCES client_cert_grants (id) ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE,
    deploy_target_id uuid        NOT NULL,
    version_id       uuid        NOT NULL,
    deploy_seq       bigint      NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX server_post_tails_target ON server_post_tails (deploy_target_id);

-- +goose Down
DROP TABLE server_post_tails;
