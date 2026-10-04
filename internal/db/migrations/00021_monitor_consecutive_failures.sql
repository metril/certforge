-- +goose Up
-- A monitor goes unreachable only after consecutive failed checks, so one
-- dropped dial does not raise an event pair; reset on any successful check.
ALTER TABLE external_monitors ADD COLUMN consecutive_failures integer NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE external_monitors DROP COLUMN consecutive_failures;
