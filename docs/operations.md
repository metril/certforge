# Operations

## Health endpoints

- `GET /healthz` — liveness. Always `200 {"status":"ok"}` if the process is up and serving HTTP; it does not touch the database.
- `GET /readyz` — readiness. Checks the database connection and the KEK canary (see [configuration.md](configuration.md#the-kek)):
  - `200 {"status":"ready","checks":{"database":"ok","kek":"ok"}}` when both checks pass.
  - `503 {"status":"unavailable","checks":{...}}` when either fails. Each entry in `checks` is `"ok"` or `"failed"` (`kek` is `"unknown"` if the database ping itself failed, since the canary could not be checked). Failure details are logged server-side, not returned, because the endpoint is unauthenticated.

`certforge healthcheck` probes `/readyz` on `CF_LISTEN_HTTP` and exits 1 if it does not return 200; use it as a container `HEALTHCHECK`.

## Running

`certforge serve` runs the HTTP server: applies migrations, checks the KEK canary, and serves the API under `/api/v1`, the health endpoints above, and the web UI (embedded when built with `-tags embedweb`, otherwise a placeholder page). See [configuration.md](configuration.md) for the environment variables it reads and the KEK.

Issuance runs as background jobs on a [river](https://riverqueue.com/) client started alongside the HTTP server: a periodic scan every 5 minutes enqueues one job per certificate due for issuance or renewal (`certforge_issue`), marks expired certificates, and closes issuance attempts left `running` for more than 4 hours (a crashed or killed worker). `POST /certificates` and `POST /certificates/{id}/renew` enqueue the same job directly; river's uniqueness options collapse a manual renew request into an already-queued or already-running scan job for the same certificate.

### Shutdown

On SIGINT/SIGTERM, `serve` drains in order:

1. The HTTP server stops accepting new requests and gives in-flight ones up to 15s to finish.
2. The river client stops fetching new jobs and gives already-running issuance jobs up to 30s to finish (`Stop`).
3. If jobs are still running after that, their contexts are cancelled and they get up to 10s more to unwind (`StopAndCancel`); a cancelled issuance attempt is recorded as failed and retried after the usual backoff, not lost. This is logged at error level with how many jobs were still running when it happened, since it means shutdown took longer than the deploy's configured grace period allowed.

That is up to ~55s end to end, so a deploy's stop timeout must allow at least that: the server's container in `deploy/compose.yaml` sets `stop_grace_period: 60s` (Docker's default is 10s, which would SIGKILL the process mid-drain and abandon whatever issuance attempts were still running instead of letting them fail cleanly and retry). A Kubernetes deployment needs the equivalent `terminationGracePeriodSeconds: 60` on the pod spec.

## Request limits

Public, unauthenticated routes (`/auth/login`, `/setup/complete`) are as exposed to a hostile client as any other, so they carry the same resource-exhaustion limits as the rest of `/api/v1` (see [security.md](security.md#resource-exhaustion-on-public-routes) for the full list and rationale):

- Request bodies over 1 MiB get `413`.
- Passwords over 1024 bytes get `422`.
- More than 4 concurrent argon2 operations server-wide get `503` with `Retry-After: 1`; a client that respects it should retry after a second rather than hammering the endpoint.
- The server's `http.Server` sets `ReadHeaderTimeout: 10s`, `ReadTimeout: 30s`, and `IdleTimeout: 120s`.
