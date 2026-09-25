# Operations

## Health endpoints

- `GET /healthz` — liveness. Always `200 {"status":"ok"}` if the process is up and serving HTTP; it does not touch the database.
- `GET /readyz` — readiness. Checks the database connection and the KEK canary (see [configuration.md](configuration.md#the-kek)):
  - `200 {"status":"ready","checks":{"database":"ok","kek":"ok"}}` when both checks pass.
  - `503 {"status":"unavailable","checks":{...}}` when either fails. Each entry in `checks` is `"ok"` or `"failed"` (`kek` is `"unknown"` if the database ping itself failed, since the canary could not be checked). Failure details are logged server-side, not returned, because the endpoint is unauthenticated.

With a failed KEK canary, `serve` still starts and answers HTTP (so `/readyz` itself, and the container orchestrator's restart/alerting on it, keep working), but it never re-chains or writes to the audit log under that boot's derived key: doing so would key rows wrong, which can never later verify under the correct key (ADR 0008). What a given request does about it depends on the handler: most audit-writing requests (session login/logout, role bindings, API keys, users, orgs, sites, settings, and so on) still succeed at the API level — the write is best-effort, and the handler logs `audit: unavailable (KEK canary failed; recording refused)` and moves on, so the request produces no audit row. A request whose audit trail is load-bearing fails closed instead: downloading a certificate's private key (`GET .../download` with a key part) returns 500 rather than release key material with no corresponding audit row, since that `Record` call's error is propagated, not logged-and-ignored. `bootstrap-admin` fails closed too, but via its own, separate KEK canary check run before it even constructs an `Auditor` — it refuses to run at all on a bad KEK, independently of `serve`'s disabled-`Auditor` gate above. `GET /api/v1/audit/verify` is not gated by any of this: it walks the chain as usual and reports it broken or fine, since `Check`/`Verify` don't go through the disabled `Record` path. Fix the KEK (`CF_KEK`/`CF_KEK_FILE`) and restart the process; on the next boot, once the canary passes, `Rechain` runs as usual and normal recording resumes. No audit data from the misconfigured window can be recovered for the requests that succeeded without one — those actions were simply never recorded.

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

## Migrations

`serve` and `migrate` apply embedded goose migrations on startup; this is safe to run repeatedly and from several processes at once. Migration `00005` reserves the org slug `all` for the web UI's All orgs route (`/o/all/...`). If an org already has that slug, the migration fails before altering the schema, with:

```
org <id> has reserved slug "all"; rename it before this migration can run
```

Rename that org (`UPDATE orgs SET slug = '<new-slug>' WHERE id = '<id>'`) and re-run migrations.

## Request limits

Public, unauthenticated routes (`/auth/login`, `/setup/complete`) are as exposed to a hostile client as any other, so they carry the same resource-exhaustion limits as the rest of `/api/v1` (see [security.md](security.md#resource-exhaustion-on-public-routes) for the full list and rationale):

- Request bodies over 1 MiB get `413`.
- Passwords over 1024 bytes get `422`.
- More than 4 concurrent argon2 operations server-wide get `503` with `Retry-After: 1`; a client that respects it should retry after a second rather than hammering the endpoint.
- The server's `http.Server` sets `ReadHeaderTimeout: 10s`, `ReadTimeout: 30s`, and `IdleTimeout: 120s`.

## Agent listener

`CF_LISTEN_AGENT` (port 8443 by default) is a second `http.Server`, entirely separate from the UI/API listener: mutual TLS, serving only `/agent/v1/*`. Its certificate is issued by the internal agent CA for Settings → Agents → listener names plus the Agent URL host, signed by the oldest non-retired agent CA so a rotation never strands an agent that has not yet picked up a new trust bundle. It is renewed automatically: an hourly river job re-checks it and re-issues once two thirds of its one-year lifetime has passed, or immediately when the signing CA or the configured names change. HTTP/2 is disabled on this listener (`TLSNextProto` cleared and `http/1.1` is the only negotiated protocol), since the WebSocket upgrade agents use needs HTTP/1.1. If the listener certificate cannot be issued at startup, the agent listener is not started, and the server must be restarted after fixing the cause.
