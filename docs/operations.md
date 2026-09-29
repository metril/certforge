# Operations

## Health endpoints {#readiness}

- `GET /healthz` — liveness. Always `200 {"status":"ok"}` if the process is up and serving HTTP; it does not touch the database.
- `GET /readyz` — readiness. Checks the database connection and the KEK canary (see [configuration.md](configuration.md#the-kek)), plus Vault reachability once either is in play:
  - `200 {"status":"ready","checks":{"database":"ok","kek":"ok"}}` when database and KEK checks pass.
  - `503 {"status":"unavailable","checks":{...}}` when either fails. Each entry in `checks` is `"ok"` or `"failed"` (`kek` is `"unknown"` if the database ping itself failed, since the canary could not be checked). Failure details are logged server-side, not returned, because the endpoint is unauthenticated.
  - `checks.vault` appears only when the server has a reason to reach Vault: the KEK is Transit (`docs/vault.md#transit-kek`), or the Integrations Vault section (`docs/vault.md#integrations`) has an address configured. It is `"ok"`, `"degraded"` or `"failed"`, based on a `sys/health` probe cached for 30 seconds — a burst of readiness polls never hammers Vault. A Transit-KEK failure is `"failed"` and makes the whole response `503`: the server cannot decrypt secrets without it. An Integrations-section failure (KEK not Transit) is `"degraded"` and leaves the server `200 ready`: that Vault only backs vaultpki CAs and vault-kv deploy targets, which fail their own way without it, and the rest of the server stays usable. Either way the body carries only the one word — never the configured address, token or any other Vault detail (R10); the redacted probe error is logged server-side.

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

## http-01 challenges

A `http-01` rule with `via: server` (the default) is answered by CertForge itself at `GET /.well-known/acme-challenge/{token}` on the main HTTP listener — unauthenticated, plain text, not under `/api/v1` (see [docs/api.md](api.md)). The ACME CA connects to the certificate's own names on port 80, so route that path to CertForge from whatever already terminates port 80 there. With nginx in front of CertForge:

```nginx
location /.well-known/acme-challenge/ {
    proxy_pass http://certforge:8080;
}
```

Do this for every name a `via: server` http-01 rule covers; a name with nothing listening on port 80 for it will fail that rule's challenge. See [docs/certificates.md#http-01](certificates.md#http-01).

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

## Agent CA rotation

1. Settings → Agents → Rotate CA (or `POST /api/v1/agents/ca/rotate`). A new CA becomes active and signs every new agent certificate; the old one is marked retiring, stays trusted, and keeps signing the listener certificate, so every agent can still connect. Connected agents receive the new trust bundle, renew at once (their new certificate comes from the new CA) and reconnect.
2. Pull-mode agents (`certforge-agent pull` from cron) and agents that were offline move when their certificate comes due for renewal (two thirds of its lifetime, 60 days by default): the renew response carries the new trust bundle. To move one sooner, re-enrol it. Watch each client's agent CA (`agentCaId` in `GET /api/v1/clients`); the CA list shows how many live agent certificates each CA still anchors.
3. When the old CA shows 0, retire it. Retiring is refused while any active client still holds an unexpired certificate from it. Retire switches the listener certificate to the new CA; by then every active agent holds a bundle that trusts it.

Enrolment tokens pin the CA that signs the listener certificate, so tokens created before or after a rotation work until the old CA is retired; after that, a token pinned to it is refused (409) and the client needs re-enrolling for a new one.

## KEK rotation

CertForge's key-encryption key (KEK) can be rotated live, with no downtime and no offline migration step (ADR 0014). `GET /api/v1/keys/status` reports the active KEK's identity, any previous KEKs still configured, a canary round-trip and the most recent rewrap's progress. Settings → Backup and keys' **Encryption key** card (`docs/web-ui.md`) shows all of this and starts a rewrap without leaving the browser.

**Static → static** (a new `CF_KEK`/`CF_KEK_FILE` value):
1. Move the current value to `CF_KEK_PREVIOUS` (or `CF_KEK_PREVIOUS_FILE`), set the new value as `CF_KEK`/`CF_KEK_FILE`, and restart.
2. Boot enqueues a rewrap automatically. Watch `GET /keys/status`'s `rewrap.remaining` (or trigger a fresh run any time with `POST /api/v1/keys/rewrap`, `settings:write`, 409 while one is already running).
3. Once `remaining` reaches 0, remove `CF_KEK_PREVIOUS[_FILE]` and restart again. Every row is now decryptable under the new KEK alone.

**Static → Vault Transit**: set `CF_KEK_PREVIOUS`/`CF_KEK_PREVIOUS_FILE` to the current static key, configure `CF_KEK_VAULT_*` for the new Transit-backed KEK (`docs/vault.md#transit-kek`), and follow the same steps. This is also the path an existing (pre-5A) install takes on its first boot after upgrading: `EnsureRoot`'s legacy lookup needs the original static KEK, as either `CF_KEK` or `CF_KEK_PREVIOUS`, to seed the sealed root secret with the exact bytes every previously-derived key (the audit HMAC key above all) already used — skipping this on that one boot fails startup outright (`settings.ErrNoLegacyRoot`) rather than silently forking the audit chain.

At most one static and one Vault-Transit previous KEK may be configured at a time (`CF_KEK_PREVIOUS[_FILE]` and `CF_KEK_PREVIOUS_VAULT_*`, same suffixes as `CF_KEK_VAULT_*`); a previous KEK removed before `remaining` reaches 0 leaves those rows undecryptable until it is reconfigured (loud failure, `crypto.ErrWrongKEK`, never silent data loss).

### Rewrap

`internal/kek.RewrapWorker` walks every sealed column (`settings`, `cas` — `eab_hmac` and `secret_cfg` together, `acme_accounts`, `dns_provider_credentials`, `output_specs`, `agent_cas`, `certificate_versions`) in keyset pages, moving each row still sealed under a previous KEK onto the active one. It rewraps the KEK canary first as a fast, explicit check: a previous KEK misconfigured or removed too soon fails the whole run immediately rather than after scanning far larger tables first. Progress is visible mid-run (`GET /keys/status`'s `rewrap` object updates after every page) and the job is safe to resume or re-run: a row already on the active KEK is a cheap no-op, and every write is a compare-and-swap, so a lost race against a concurrent write is simply counted in `remaining` and retried by the next run instead of overwriting data the job never decrypted.

## Backup {#backup}

A backup is a single self-contained `.cfbak` file: a magic string, a plaintext JSON header, then the database's own snapshot, AES-256-GCM encrypted in 64 KiB chunks (`internal/backup`, ADR 0018). Nothing about the format needs a running CertForge server or Postgres to inspect the header — only to restore it.

**What's in it.** A `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY` transaction takes one consistent snapshot of every application table (`backup.Manifest`: everything from `internal/db/migrations`, `goose_db_version` included so the exact schema version is provable, no `river_*` table — a restore re-applies river's own schema instead of copying its queue). The header records that snapshot's migration version, the KEK id(s) in play, a fresh random salt, and the sealed `crypto.root` row itself; the rest of the file is the tables' CSV dump, tarred and chunk-encrypted, with a final `manifest.json` entry recording each table's row count and content hash.

**Key derivation.** The header is plaintext by design — identifying a backup (its date, its KEK id) needs no key — but every chunk's ciphertext is bound to it: the AAD is `sha256(magic‖header)‖chunk index‖final flag`, so a byte flipped anywhere in the header, a dropped final chunk, a reordered chunk or trailing garbage all fail AES-GCM authentication instead of silently decrypting something else. The stream key itself is `DeriveKey(DeriveKey(root, "certforge-backup"), hex(salt))` — two HKDF-SHA256 steps off the same root secret every other derived key comes from (`security.md#root-secret`), never off the KEK's raw bytes, and never reused across two backups since the salt is fresh every time.

**KEK escrow.** Restoring a backup needs the same KEK (active or previous) that sealed it: `Header.RootSealed` is the raw sealed `crypto.root` row, and restore's very first step is proving the configured KEK can unseal that exact value, before touching the database at all. A KEK that is lost entirely makes every backup taken under it permanently unrestorable — there is no recovery path around this, by design (`security.md#kek-handling`). Escrow the KEK before relying on backups; both the CLI and the API refuse to create one until that escrow is confirmed.

**Restore.** Restore migrates the target database up to `max(header.MigrationVersion, 13)` — migration 13 is the first version whose foreign keys are all `DEFERRABLE`, which restoring depends on — then loads every table inside one transaction with `SET CONSTRAINTS ALL DEFERRED`, verifying each one's row count and content hash against the archive's own manifest before it will commit. Before commit, the freshly loaded `crypto.root` row must equal the header's byte for byte and the canary must still open under the configured KEK; either failure rolls the whole transaction back, so a wrong KEK, a truncated file, or a tampered archive never leaves the database partially loaded. `audit_events` is append-only even to a restore (`internal/db/migrations/00001_init.sql`'s triggers refuse to truncate or delete it under any role) — its rows are still loaded, as inserts on top of whatever the target already had, never replacing history.

**CLI: `certforge backup`.**

```
certforge backup --out <path|-> [--kek-escrowed]
```

Streams one archive to `--out` (a `.tmp` file next to it, renamed into place on success — a reader never sees a partial file at the final name) or to stdout with `--out -`. Refuses with a redacted, plain-text error and writes nothing if the `backup` settings section's `kekEscrowConfirmed` is off; `--kek-escrowed` overrides that check for one run (for example scripting a first backup before the setting has been saved through the UI). `backup` takes no advisory lock and runs safely alongside a live server — it only opens a read-only snapshot transaction, the same one the scheduled job (`docs/operations.md#backup-schedule`) uses.

## Restore {#restore}

Restore is CLI-only — there is no HTTP restore endpoint — and it is the one operation that requires the server to be stopped first:

```
certforge restore --in <path|-> [--yes]
```

1. **Stop the server.** `restore` takes `ServeLockKey` exclusively; a running `serve` process holds it shared, so restore refuses immediately with "a certforge server is running against this database; stop it first" (`internal/backup.ErrServerRunning`) rather than blocking. Conversely, `serve` cannot start while a restore is mid-flight — its own shared-lock attempt (`pg_try_advisory_lock_shared`) also fails immediately, with "a restore holds the database lock", rather than waiting for the restore to finish.
2. **Preview, then confirm.** Without `--yes`, restore only reads the archive's plaintext header — no database connection is opened at all — and prints `createdAt`, `appVersion`, `migrationVersion` and `activeKekId`, then exits 2. Re-run with `--yes` once that header is the one you expect.
3. **Restore.** With `--yes`, restore also refuses a target database whose `audit_events` table is not empty ("restore into a fresh database"): point it at a fresh, never-booted database, not one already in service. It unseals the archive with the configured KEK (active, or any configured previous KEK), refusing with nothing written if none matches (`internal/backup.ErrKEKMismatch`) — the same KEK escrow that sealed the backup is what makes restoring it onto a replacement host possible. On success it appends `restore.completed` (`archiveCreatedAt`, `migrationVersion`, `tables`) to the audit chain as the `cli` actor.
4. **Start the server.** Once restore reports success, `certforge serve` can start normally against the restored database.

Piped through a compose service:

```
docker compose run --rm -T certforge restore --in - --yes < backup.cfbak
```

(`-T` disables the pseudo-TTY compose would otherwise allocate, which would corrupt the binary stream on stdin.)
