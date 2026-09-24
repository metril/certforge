# Operations

## Health endpoints

- `GET /healthz` — liveness. Always `200 {"status":"ok"}` if the process is up and serving HTTP; it does not touch the database.
- `GET /readyz` — readiness. Checks the database connection and the KEK canary (see [configuration.md](configuration.md#the-kek)):
  - `200 {"status":"ready","checks":{"database":"ok","kek":"ok"}}` when both checks pass.
  - `503 {"status":"unavailable","checks":{...}}` when either fails. Each entry in `checks` is `"ok"` or `"failed"` (`kek` is `"unknown"` if the database ping itself failed, since the canary could not be checked). Failure details are logged server-side, not returned, because the endpoint is unauthenticated.

`certforge healthcheck` probes `/readyz` on `CF_LISTEN_HTTP` and exits 1 if it does not return 200; use it as a container `HEALTHCHECK`.

## Running

`certforge serve` runs the HTTP server: applies migrations, checks the KEK canary, and serves the API under `/api/v1`, the health endpoints above, and the web UI (embedded when built with `-tags embedweb`, otherwise a placeholder page). See [configuration.md](configuration.md) for the environment variables it reads and the KEK.

## Request limits

Public, unauthenticated routes (`/auth/login`, `/setup/complete`) are as exposed to a hostile client as any other, so they carry the same resource-exhaustion limits as the rest of `/api/v1` (see [security.md](security.md#resource-exhaustion-on-public-routes) for the full list and rationale):

- Request bodies over 1 MiB get `413`.
- Passwords over 1024 bytes get `422`.
- More than 4 concurrent argon2 operations server-wide get `503` with `Retry-After: 1`; a client that respects it should retry after a second rather than hammering the endpoint.
- The server's `http.Server` sets `ReadHeaderTimeout: 10s`, `ReadTimeout: 30s`, and `IdleTimeout: 120s`.
