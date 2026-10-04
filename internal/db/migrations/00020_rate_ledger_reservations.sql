-- +goose Up
-- Atomic rate ledger: an issue attempt reserves its new_order / cert_issued
-- rows in one short locked transaction (ReserveLedger). attempt_id ties the
-- rows to the attempt; reserved_until is set on cert_issued rows while they
-- are only reserved and cleared on success. An expired reservation (a worker
-- that crashed) stops counting and is pruned.
ALTER TABLE rate_ledger ADD COLUMN attempt_id uuid;
ALTER TABLE rate_ledger ADD COLUMN reserved_until timestamptz;
CREATE INDEX rate_ledger_attempt_idx ON rate_ledger (attempt_id) WHERE attempt_id IS NOT NULL;

-- +goose Down
DROP INDEX rate_ledger_attempt_idx;
ALTER TABLE rate_ledger DROP COLUMN reserved_until;
ALTER TABLE rate_ledger DROP COLUMN attempt_id;
