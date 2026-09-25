-- +goose Up
CREATE INDEX audit_events_ts_id ON audit_events (ts DESC, id DESC);
CREATE INDEX audit_events_org ON audit_events (org_id);
CREATE INDEX audit_events_actor ON audit_events (actor_id);
CREATE INDEX audit_events_resource ON audit_events (resource_type, resource_id);
CREATE INDEX audit_events_action ON audit_events (action);

-- +goose Down
DROP INDEX audit_events_action;
DROP INDEX audit_events_resource;
DROP INDEX audit_events_actor;
DROP INDEX audit_events_org;
DROP INDEX audit_events_ts_id;
