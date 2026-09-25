# Architecture

## Components (Phase 1A)

```mermaid
flowchart LR
  Browser -->|HTTPS cookie + CSRF| Router
  CLI[API clients] -->|HTTPS| Router
  subgraph certforge [certforge serve]
    Router[chi router: recoverer + securityHeaders] --> Health[/healthz, /readyz/]
    Router --> Docs[/api/docs/*, static Swagger UI/]
    Router --> V1[/api/v1: withClientIP + requireJSON + authn.Middleware/]
    Router --> RootNF[root NotFound]
    Router --> RootMNA[root MethodNotAllowed]
    V1 --> OpenAPI[/api/v1/openapi.json, public/]
    V1 --> Strict[oapi-codegen strict server]
    RootNF -->|/api/* path| ProblemJSON404[problem+json 404]
    RootNF -->|any other path| WebUI[embedded SPA, index.html fallback]
    RootMNA -->|/api/* path| ProblemJSON405[problem+json 405]
    RootMNA -->|any other path| PlainText405[plain-text 405]
    Strict --> Authz[authz.Can]
    Strict --> Settings[settings.Store]
    Strict --> Setup[setup.Service]
    Strict --> Audit[audit.Auditor]
    Settings --> Envelope[crypto.Envelope]
    Envelope --> KEK[KeyWrapper: env/file KEK]
  end
  V1 --> PG[(Postgres 16)]
  Settings --> PG
  Audit --> PG
```

| Package | Role |
|---|---|
| `internal/config` | Reads the only env vars: DB URL, KEK, listeners, base URL, log level |
| `internal/db` | pgx pool, embedded goose migrations (Postgres session-locked, safe to run repeatedly and from several processes), sqlc queries |
| `internal/crypto` | Envelope encryption, `KeyWrapper` |
| `internal/settings` | Settings table: JSON values, sealed secrets, JSON-Schema sections, KEK canary |
| `internal/authn` | argon2id local admin, Postgres sessions, CSRF, `Principal` in context |
| `internal/authz` | Roles → actions, org-scoped bindings, `Can()` |
| `internal/audit` | Append-only, SHA-256 hash-chained events |
| `internal/meta` | Registry of pluggable type schemas for `GET /api/v1/meta/schemas` |
| `internal/setup` | First-run wizard, bootstrap-admin |
| `internal/api` | Router, handlers, problem+json, generated server in `gen/` |
| `internal/webui` | Embedded SPA with index.html fallback (placeholder page unless built with `-tags embedweb`) |

`deploy/compose.yaml` publishes the agent mTLS port (`${CF_AGENT_PORT:-8443}:8443`) alongside the HTTP port, but nothing listens on `:8443` yet; the agent listener is Phase 3 work.

## Startup

1. `config.Load` validates env; a bad KEK length or missing DB URL exits.
2. `db.Open` pings Postgres; `db.Migrate` applies pending migrations under a Postgres session lock.
3. `settings.EnsureCanary` writes the `crypto.canary` secret on first boot, or decrypts it. On failure the server still starts, logs the error, and `/readyz` returns 503.
4. The router is built and serves on `CF_LISTEN_HTTP`. An hourly goroutine purges expired sessions.

## Request path

At the router root, `recoverer` (a local replacement for chi's `middleware.Recoverer`, so a panic becomes a `problem+json` 500 with a logged stack instead of a bare 500) and `securityHeaders` wrap everything, including `/healthz`, `/readyz`, and `/api/docs/*`. Under `/api/v1`: `withClientIP` → `requireJSON` (415 for non-JSON bodies on POST/PUT/PATCH) → `authn.Middleware` (session cookie → `Principal`, CSRF check on mutating methods, 401 unless the route is in `isPublic`) → the oapi-codegen strict handler → `authorize()` (`authz.Can`) → store or service → `audit.Record`.

Root-level `NotFound` and `MethodNotAllowed` handlers both branch on path prefix, but only `NotFound` falls through to the web UI: for a path under `/api/`, `NotFound` returns `problem+json` 404 and `MethodNotAllowed` returns `problem+json` 405; for any other path, `NotFound` falls through to the embedded SPA handler (`webui.Handler()`), which serves `index.html` so client-side routes resolve, while `MethodNotAllowed` returns a plain-text 405 (`http.Error`), not the SPA. Within `/api/v1`, unmatched paths and methods also return `problem+json`. Handler errors of type `*api.HTTPError` become `problem+json`; any other error is logged and then also written as a `problem+json` 500 (`Write(w, 500, "Internal server error", "")`), not a bare 500.

`authn.LoadPrincipal` builds `Principal.Roles`/`Bindings`/`OrgIDs` from `role_bindings`; a binding with a non-NULL `site_id` is skipped entirely until site scope is modelled in Phase 2, so it currently grants nothing. Login (`POST /api/v1/auth/login`) and setup completion (`POST /api/v1/setup/complete`) both build the full principal (via `finishSession`) before `startSession` sets the `cf_session` cookie; if anything after session creation fails, the session row is deleted best-effort so a failed login never leaves a live cookie or session behind.

## Envelope encryption

```mermaid
flowchart LR
  PT[plaintext] -->|AES-256-GCM, AAD=kek_id| CT[ciphertext]
  DEK[random 32-byte DEK] --> CT
  DEK -->|AES-256-GCM with KEK, AAD='certforge-dek:'+kek_id| WDEK[wrapped DEK]
  CT & WDEK --> Blob
```

Blob bytes: `0x01 | len(kek_id) | kek_id | u16 len(wrapped) | wrapped | len(nonce) | nonce | ciphertext`. `kek_id` (`crypto.KeyID`) is `static-` plus 16 hex characters of a domain-separated hash, `SHA-256("certforge-kek-id:" || key)`, not a plain SHA-256 of the key, so a different KEK is detected before any decryption. `Decrypt` validates every length and never panics on malformed input. Phase 5 adds a Vault Transit `KeyWrapper` and rewrap.

## Data model (Phase 1A)

`orgs`, `sites` (org-scoped), `users` (at most one with `local_password_hash`, enforced by a partial unique index), `sessions` (id = SHA-256 of the cookie token, per-session CSRF), `role_bindings` (subject, role, optional org and site; the `role` check constraint is `admin`, `org-admin`, `operator`, `viewer`, `auditor`), `settings` (key, jsonb value, sealed bytea secret), `audit_events` (append-only via triggers that block UPDATE/DELETE/TRUNCATE, `prev_hash` unique).

## Setup and bootstrap

`setup.Service.Complete` short-circuits (`ErrAlreadyComplete`) as soon as `NeedsSetup` reports false, before hashing a password or taking the advisory lock, then re-checks under the lock so a concurrent completer cannot race past the short-circuit. It validates `baseUrl` twice: `config.ValidateBaseURL` for a well-formed absolute http(s) URL, then against the `general` settings section's JSON Schema (the same schema `PUT /api/v1/settings/general` enforces), so setup never accepts a `baseUrl` a later unchanged `PUT` of that section would reject.

`cmd/certforge bootstrap-admin` reads `CF_ADMIN_PASSWORD` as one-shot CLI input (or `--password-stdin`) to reset (after setup) the local admin's password and revoke its sessions; it is not server configuration and `serve` never reads that variable.

## Extension points

- New API operation: `api/openapi.yaml` → `make generate` → method on `*api.Server`.
- New settings section: `sections.MustRegister(name, schema, default)` in `cmd/certforge/serve.go`.
- New pluggable type: `metaReg.Add(meta.Kind..., meta.Entry{...})` in `serve.go`.

## Routing challenge provider

lego sees one DNS-01 provider per issuance: `challenge.Router`. It is built per attempt from the certificate's verification rules followed by the inherited catch-all rules (certificate overrides, then org, then global defaults). See [ADR 0005](adr/0005-routing-challenge-provider.md).

```mermaid
flowchart LR
  L[lego DNS-01 solver] -->|Present / CleanUp / PreCheck| R[challenge.Router]
  R -->|first matching rule| P1[lego provider<br/>credential A]
  R --> P2[lego provider<br/>credential B]
  R --> M[ManualProvider]
  M --> DB[(manual_dns_pending)]
  R -->|rule resolvers set| C[CheckTXT on those resolvers]
  R -->|none set| D[lego default propagation check]
```

- Match patterns: `*`, `*.zone` (one label below zone, or `*.zone` itself), `zone` (zone and everything below). First match wins. The UI's coverage panel uses the same rules.
- `Router.Validate` rejects uncovered names and IP addresses before an order exists.
- lego providers are built by `challenge.Build` under a global mutex with an isolated environment (`internal/challenge/lego_env.go`).
- Provider schemas are generated from lego's TOML metadata by `tools/gen-lego-schemas` into `internal/challenge/schemas/` and published to the meta registry by `challenge.AddToMeta` and served under `dnsProviders` in `GET /api/v1/meta/schemas`.

## Issuance flow

```mermaid
sequenceDiagram
  participant P as river periodic (5 min)
  participant S as ScheduleWorker
  participant Q as river queue
  participant W as IssueWorker
  participant CA as ACME CA
  P->>S: certforge_schedule
  S->>S: mark expired, close stale attempts
  S->>Q: certforge_issue{cert_id} per due cert (unique while queued/running)
  Q->>W: job
  W->>W: attempt row, steps caa/rate_ledger = skipped
  W->>W: resolve effective config, load CA + account
  W->>W: build Router, Validate names
  W->>CA: lego Obtain (Present, PreCheck, validate, finalize)
  alt success
    W->>W: tx: insert version (key sealed), next_renew_at, attempt success
  else failure
    W->>W: attempt failed, backoff min(5m·2^n, 24h) ±20%, Retry-After wins
  end
```

- `POST /certificates` and `POST /certificates/{id}/renew` enqueue the same job directly.
- Attempt steps: `caa`, `rate_ledger` (skipped until Phase 4), `account`, `order`, `challenge <name>` (one per name; `waiting_manual` while an operator must act), `finalize`, `store`.
- ACME and challenge failures are recorded and scheduled through `certificates.next_renew_at`; the job itself succeeds. Only database errors make river retry the job.
- `next_renew_at` after success: `days` mode is `notAfter − N days`, `percent` mode is `notAfter − N% of lifetime`, never earlier than half the lifetime. ARI (`useAri`) is stored and ignored until Phase 4.
- A failed renewal keeps a still-valid certificate `active`; the periodic scan marks certificates `expired` when the current version's `notAfter` passes.

## Grants and revisions

```mermaid
flowchart LR
  V[IssueWorker commits a version] -->|OnVersion| R[agents.render]
  G[Grant, layout, target or hook change] --> R
  R -->|same tx| D[(deployments.expected, state pending)]
  R -->|same tx| B[(clients.desired_revision + 1)]
  B -->|after commit, push grants| S[hub: sync{revision}]
```

A grant is a client × certificate assignment with a layout and/or a deploy target, a run-ordered list of hooks and a delivery mode (`push` or `pull`); `deployments.expected` holds the digests the server rendered for the grant's certificate's current version, and `deployments.installed`/`state` hold what the agent last reported. Every grant create, update, redeploy or delete, every layout, deploy target or hook change, and every new certificate version re-renders the affected grants' `deployments.expected` and bumps `clients.desired_revision` inside the same transaction as the change; a `sync{revision}` nudge is sent over the hub after commit, but only to clients that have a push grant among the changed ones — pull grants wait for the agent's own pull schedule, so a change touching only pull grants never nudges.

A new certificate version is rendered by `agents.Service.OnVersion` (the `issuance.VersionListener`) in its own transaction after the issuance commit, not the issuance transaction itself; a failed or lost `OnVersion` (for example the process stopping between commit and the listener call) is caught by an hourly river job, `SweepDeployments`, that re-renders every live grant whose deployment is behind its certificate's current version. Two grants on one client may never write the same path — including a Traefik target's generated `certs/<SafeName>/*` files, so two certificates whose names share a `SafeName` collide — checked across the client's live grants and any still awaiting removal (their last-rendered `expected` paths count too); a conflicting create, update or layout/target update returns 409. Deleting a grant of an enrolled agent marks it `removed_at` and bumps the revision so the agent can delete its files on its own schedule; the row is only deleted once the agent's next report confirms the files are gone. A grant of a client that never enrolled, or is revoked, has no agent to act on it, so the delete removes the row at once.
