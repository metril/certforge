-- +goose Up
-- Every append takes the serialised audit lock, so each extra index is paid
-- for under it. audit_events_org is the prefix of audit_events_org_ts;
-- audit_events_action cannot serve the prefix (starts_with) filter and an
-- equality on it is low-selectivity. List/export order by the primary key,
-- so a (ts DESC, id DESC) btree only helps ranges; ts is stamped under the
-- chain lock and is therefore monotonic with id, which is what a BRIN needs.
DROP INDEX audit_events_org;
DROP INDEX audit_events_action;
DROP INDEX audit_events_ts_id;
CREATE INDEX audit_events_ts_brin ON audit_events USING brin (ts);

-- +goose Down
DROP INDEX audit_events_ts_brin;
CREATE INDEX audit_events_action ON audit_events (action);
CREATE INDEX audit_events_org ON audit_events (org_id);
CREATE INDEX audit_events_ts_id ON audit_events (ts DESC, id DESC);
