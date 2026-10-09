-- +goose Up
-- The last signed CRL per CA issuer, so the public CRL route serves stored
-- DER and only re-signs (taking a new cRLNumber) when the revoked set
-- changed (revision = cas.crl_number at signing) or next_update nears.
CREATE TABLE ca_crls (
    ca_id         uuid        NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
    issuer_serial text        NOT NULL,
    crl_number    bigint      NOT NULL,
    revision      bigint      NOT NULL,
    der           bytea       NOT NULL,
    this_update   timestamptz NOT NULL,
    next_update   timestamptz NOT NULL,
    PRIMARY KEY (ca_id, issuer_serial)
);

-- +goose Down
DROP TABLE ca_crls;
