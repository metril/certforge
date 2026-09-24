# Configuration

CertForge is configured from the web UI. The environment only carries what the server needs before it can reach and decrypt its database.

## Bootstrap environment variables

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `CF_DATABASE_URL` | yes | – | Postgres URL, for example `postgres://certforge:pw@postgres:5432/certforge?sslmode=disable` |
| `CF_KEK` | one of these two | – | Key-encryption key: 32 random bytes, base64 |
| `CF_KEK_FILE` | one of these two | – | Path to a file with the KEK (base64, or exactly 32 raw bytes) |
| `CF_LISTEN_HTTP` | no | `:8080` | UI and API listener |
| `CF_LISTEN_AGENT` | no | `:8443` | Agent mTLS listener (Phase 3) |
| `CF_BASE_URL` | no | – | Public URL. The setup wizard stores its own value in Settings → General, which takes precedence |
| `CF_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error` |

## The KEK

Generate one:

```bash
head -c 32 /dev/urandom | base64
```

Losing the KEK means losing every private key and secret in the database. Store a copy outside the server before issuing anything. The server derives a KEK id from the key, stores it with every encrypted row, and checks a canary at startup. With the wrong KEK, `/readyz` reports `kek: failed`.

For `CF_KEK_FILE` in the container, the file must be readable by uid 65532: `chown 65532 kek && chmod 0400 kek`.

## Settings framework

Live configuration is stored in the `settings` table (`key`, JSON `value`, encrypted `secret`) and edited from the UI without a restart.

- Each Settings page is a **section** with a JSON Schema. `GET /api/v1/settings/{section}` returns `{section, schema, value}`. `PUT` takes the value object, validates it against the schema (422 on failure), and stores it under the key `section.<name>`. An unset section returns its default.
- Phase 1 sections: `general` (`baseUrl`), `backup` (`kekEscrowConfirmed`), and `issuance_defaults` (from the issuance plan).
- Secrets are stored with envelope encryption in the `secret` column and are never returned by the API.
