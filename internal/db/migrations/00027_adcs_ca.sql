-- +goose Up
-- A fourth CA kind: adcs enrols leaves from Microsoft AD CS through the
-- enrollment policy/enrollment web services (MS-XCEP / MS-WSTEP). Its
-- service-account password is sealed in cas.secret_cfg.
ALTER TABLE cas DROP CONSTRAINT cas_type_check;
ALTER TABLE cas ADD CONSTRAINT cas_type_check CHECK (type IN ('acme', 'localca', 'vaultpki', 'adcs'));

-- +goose Down
-- An adcs CA has no meaning once the kind is gone; its certificate versions
-- keep their data (ca_id is set NULL by the foreign key).
DELETE FROM cas WHERE type = 'adcs';
ALTER TABLE cas DROP CONSTRAINT cas_type_check;
ALTER TABLE cas ADD CONSTRAINT cas_type_check CHECK (type IN ('acme', 'localca', 'vaultpki'));
