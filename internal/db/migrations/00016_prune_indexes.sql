-- +goose Up
-- The scheduler's housekeeping now prunes issuance_attempts and hook_runs by
-- age; these indexes keep those deletes (and the cutoff scans behind them)
-- off a sequential scan. rate_ledger.cert_id is a foreign key with
-- ON DELETE SET NULL, so deleting a certificate otherwise scans the whole
-- ledger to find its rows; the index is partial because most rows (every
-- new_order) carry no cert_id.
CREATE INDEX issuance_attempts_started_at_idx ON issuance_attempts (started_at);
CREATE INDEX hook_runs_ran_at_idx ON hook_runs (ran_at);
CREATE INDEX rate_ledger_cert_id_idx ON rate_ledger (cert_id) WHERE cert_id IS NOT NULL;

-- +goose Down
DROP INDEX rate_ledger_cert_id_idx;
DROP INDEX hook_runs_ran_at_idx;
DROP INDEX issuance_attempts_started_at_idx;
