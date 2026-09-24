# CertForge progress

Single status file. Updated in every commit that completes a task.

## Phases

| # | Phase | Status | Spec | Plan | Started | Finished |
|---|---|---|---|---|---|---|
| 1 | Core issuance slice | in progress | [design](design.md) | [1A](superpowers/plans/2026-09-24-phase-1a-backend-foundation.md) · [1B](superpowers/plans/2026-09-24-phase-1b-issuance-engine.md) | 2026-09-24 | – |
| 2 | Identity and tenancy | planned | [design](design.md) | – | – | – |
| 3 | Agent | planned | [design](design.md) | – | – | – |
| 4 | Issuance breadth and formats | planned | [design](design.md) | – | – | – |
| 5 | Vault and private CA | planned | [design](design.md) | – | – | – |
| 6 | Ops | planned | [design](design.md) | – | – | – |
| 7 | Deploy targets | planned | [design](design.md) | – | – | – |

## Active phase tasks

Phase 1 is split into three plans: 1A backend foundation, 1B issuance, 1C web UI.

### Phase 1A: backend foundation — done (finished 2026-09-24) ([plan](superpowers/plans/2026-09-24-phase-1a-backend-foundation.md))

| # | Task | Status | Commit |
|---|---|---|---|
| 1 | Scaffold, Makefile, CI, lint | done | bf1241e |
| 2 | Bootstrap config | done | d487450 |
| 3 | Database, migrations, sqlc | done | f9421d2 |
| 4 | Envelope encryption | done | 5fdb42a |
| 5 | Settings store, sections, canary | done | a53929d |
| 6 | Local admin auth, sessions, CSRF | done | 277126d |
| 7 | Authorization | done | 6bff6f1 |
| 8 | Audit log | done | ef291d3 |
| 9 | OpenAPI skeleton, router, problem+json | done | 2cd22ee |
| 10 | Auth and settings endpoints | done | 1d8d3ab |
| 11 | Setup wizard and bootstrap-admin | done | d273abb |
| 12 | Health, web UI placeholder, serve | done | 519abbe |
| 13 | Container image and compose | done | 17455a8 |
| 14 | Architecture docs and phase close-out | done | b5b8802 |

Phase 1A complete; 1B (issuance) and 1C (web UI) build on it. Task 14's row
records b5b8802, the phase-closing final-review fix commit that closed out
Phase 1A; 4ea34b6 was Task 14's own last commit.

### Phase 1B: issuance engine — in progress (started 2026-09-24) ([plan](superpowers/plans/2026-09-24-phase-1b-issuance-engine.md))

| # | Task | Status | Commit |
|---|---|---|---|
| 1 | Issuance schema and sealed columns | done | 5aa9f7e |
| 2 | Challenge router and matchers | done | f92099f |
| 3 | Lego provider schemas | done | pending |
| 4 | Credential config and env-isolated provider build | todo | – |
| 5 | manual-dns provider | todo | – |
| 6 | Signer interface and ACME signer | todo | – |
| 7 | PEM renderer | todo | – |
| 8 | Defaults resolver, renewal policy, backoff, timeline | todo | – |
| 9 | Issuance data layer | todo | – |
| 10 | Certificate store and IssueWorker | todo | – |
| 11 | Scheduler, river wiring, issuance service | todo | – |
| 12 | API: CAs, accounts, defaults | todo | – |
| 13 | API: DNS credentials | todo | – |
| 14 | API: certificates, downloads, manual-dns | todo | – |
| 15 | Pebble end-to-end test | todo | – |

## Decisions made during implementation

- CF_LOG_LEVEL is read from the environment in addition to the spec's bootstrap list, because the log level is needed before the database is reachable.
- bootstrap-admin reads CF_ADMIN_PASSWORD as one-shot CLI input; it is not server configuration and serve never reads it.
- LoadPrincipal ignores site-scoped role bindings (non-NULL site_id): they contribute nothing to a principal until site scope is modelled in Phase 2.
- The router has a local recoverer (panics become problem+json 500s, not bare ones) and the root NotFound/MethodNotAllowed handlers return problem+json for any `/api/*` path.
- Outside `/api/*`, the root NotFound handler serves the embedded SPA's index.html for any unmatched path, so client-side routes resolve without a route list in the Go router.
- Login and setup-complete build the full principal before starting the session; the cf_session cookie is set only once every step has succeeded, and a partially-failed login/setup deletes the session row it created.
- setup.Service.Complete validates baseUrl against the general settings section's JSON Schema (the same schema PUT /settings/general enforces) in addition to config.ValidateBaseURL, and short-circuits with ErrAlreadyComplete as soon as setup is already done.
- `make e2e` runs under the isolated compose project `certforge-e2e` (not the dev stack's `certforge` project), with host ports overridable via CF_HTTP_PORT, CF_AGENT_PORT, and CF_CHALLTESTSRV_PORT.
- Pebble's ACME and management ports are published to the host in `deploy/compose.test.yaml` (`CF_PEBBLE_PORT` default 14000, `CF_PEBBLE_MGMT_PORT` default 15000), not just reachable over the compose network, because plan 1B's issuance e2e runs as a host-side `go test` process and needs to reach `:15000/intermediates/0` directly.
- 1B: certificate overrides and org defaults are one jsonb document (`issuance.Defaults`) instead of nullable columns; one Go type serves all three levels.
- 1B: CAs are org-scoped rows in Phase 1 (`shared` reserved for Phase 2 global CAs); only a global admin (`cas:write`) edits them.
- 1A final-review housekeeping folded into 1B Task 1: `dummyHash` (authn) now builds without the argon2 semaphore so a saturated first call cannot permanently disable `EqualizeTiming`; the semaphore release closure now captures the channel it acquired instead of re-reading the package variable; `settings.EnsureCanary`'s insert-if-absent write is now insert-or-fill, treating a `crypto.canary` row with a NULL secret as absent; docs/architecture.md and the `bootstrap-admin` help summary now say "reset (after setup)" instead of "create or reset".
- 1B: verification rule `match` follows plan 1C's matcher: `*`, `*.zone` (one label below zone, or `*.zone` itself), `zone` (zone and everything below). There is no separate exact-only syntax; list a name's own rule first.
- 1B: DNS propagation checks against configured resolvers use CertForge's own TXT query (`challenge.CheckTXT`) because lego v4's `AddRecursiveNameservers` is process-global.
- 1B: lego pinned at v4.24.0, the last v4 release whose go.mod allows Go 1.23. lego `exec` and `manual` providers are not offered.

## Known gaps

- Pebble and challtestsrv images are pinned to tag 2.10.1, not a digest; pin digests when the issuance e2e lands.
- Audit log tamper-evidence hardening not yet done: keyed HMAC instead of a plain hash, anchoring the head hash outside the table, and running the app under a role that does not own `audit_events`.
- Login attempts are not rate limited yet (argon2id cost only); add per-IP throttling with the Phase 2 auth work.
- Settings sections cannot hold secret fields yet; add write-only secret: true support when the first secret-bearing section lands (Phase 2 OIDC).
- Base images are unpinned or ageing: the server image's `golang:1.23-alpine` build stage is already out of upstream support; bump the Go builder image (and pin image tags to digests) before cutting a release tag.
- HEAD requests to `/healthz` and `/readyz` return 405 (only GET is registered for them).
- The SPA fallback (root NotFound) answers non-GET methods with `index.html` instead of 404/405, since it does not check the request method.
- A new login does not revoke the caller's existing sessions, so an old session survives a new login; only bootstrap-admin revokes sessions today.
- The viewer role's "read-only, no secrets" guarantee has nothing to enforce yet in Phase 1A (no secret-bearing read endpoint exists); it depends on plan 1B's read handlers redacting secret fields correctly.
- Encrypted blobs are not bound to their row: the AAD is the KEK id only, not a per-row identifier, so per-row AAD binding is deferred.
- The OpenAPI spec lists only 2xx responses; it does not document the 4xx/5xx problem+json responses handlers actually return.
- A valid session on a public route (for example `POST /api/v1/auth/login` while already logged in) still requires the CSRF header, since `authn.Middleware` checks CSRF whenever a session resolves, regardless of the route's public status.
- Audit event IPs are whatever `r.RemoteAddr` reports; behind a reverse proxy that is the proxy's address, not the client's. Add a trusted-proxy setting in Phase 2.
- `CF_KEK_FILE` accepts a raw 32-byte key file as-is, before trying base64 decoding; only `CF_KEK` (the env var) requires base64.
- No CSP or HSTS headers yet; add them with the real UI in Phase 1C.
