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
| 3 | Lego provider schemas | done | ad0e753 |
| 4 | Credential config and env-isolated provider build | done | 245a832 |
| 5 | manual-dns provider | done | 449429b |
| 6 | Signer interface and ACME signer | done | a57f758 |
| 7 | PEM renderer | done | bdf741e |
| 8 | Defaults resolver, renewal policy, backoff, timeline | done | b66a1b3 |
| 9 | Issuance data layer | done | dacbf57 |
| 10 | Certificate store and IssueWorker | done | 3df0fe4 |
| 11 | Scheduler, river wiring, issuance service | done | 2ee0a17 |
| 12 | API: CAs, accounts, defaults | done | 018cfca |
| 13 | API: DNS credentials | done | pending |
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
- 1B: the ACME signer's lego `http.Client` transport is `ctxTransport` (checks the issuance ctx before every request, attaches it to each one) wrapping `retryAfterTransport` (records the largest Retry-After on 429/503, since lego's `ProblemDetails` drops response headers); cancelling the issuance context now fails every in-flight CA call promptly, not just manual-dns waits.
- 1B: `renewPolicy.useAri` is stored but ARI scheduling is Phase 4; CAA and rate-ledger steps are recorded as `skipped` until Phase 4.
- 1B: defaults cover CA, account, key type, renewal, chain, reuse key, must-staple, rules, propagation and resolvers; hooks, notification channels and deploy targets join the same `Defaults` type in Phases 3 and 6.
- 1B: deleting an ACME account removes it from CertForge only; it is not deactivated at the CA.
- 1B (P34): org issuance defaults and certificate overrides already checked that a referenced `caId`/`accountId`/rule `dnsCredentialId` belongs to the caller's org. The global `issuance_defaults` settings section is not org-scoped (it applies across every org), so `(*Store).ValidateGlobalDefaults` checks existence only (new `GetCAByID`/`GetAccountByID`/`DNSCredentialExists` queries, ignoring `org_id`) plus that an `accountId` alongside a `caId` actually belongs to it; which org a global reference resolves in remains Phase 2. Deleting a CA, account or DNS credential now also checks the global section (`globalDefaultsReference`), not just org-scoped `Count*Users`, so a globally referenced row can't be deleted out from under it. The settings write path (Task 12's `PUT /settings/issuance_defaults` handler) calls this (its transactional, lock-taking sibling `ValidateGlobalDefaultsTx`, per Task 12's fix round 1) before storing the section, instead of relying on the JSON Schema alone.
- 1B: `challenge.SplitConfig`'s "unknown DNS provider" and "`__unchanged__` on create" errors are now sentinel-wrapped (`ErrUnknownProvider`, `ErrUnchangedOnCreate`) so `issuance.splitErr` classifies them with `errors.Is` instead of matching substrings of `Error()`.
- 1B: fixed from Task 8's review, same package — `NextRenewAt`'s percent branch now divides by 100 before multiplying by the policy value, so a very large certificate lifetime can't overflow int64 nanoseconds; the `issuance_defaults` schema now caps `renewPolicy.value` at 99 when `mode` is `percent` (an `if`/`then`, days keeps its plain 1..365 range) and its `verificationRules` description now says a lower level's list replaces the higher level's (null inherits), not "appended"; `Timeline.Step`/`Logf`/`Finish` now call `save` while still holding the lock, so two concurrent updates can no longer have their saves land out of order; `setLocked` now clears a step's `FinishedAt` when it returns to a non-terminal status (a retried step no longer keeps a stale finish time).
- 1B: `db.Migrate` also applies river's schema under an advisory lock; river `RescueStuckJobsAfter` = 4 h, above the 3 h IssueWorker timeout needed for manual-dns waits.
- 1B: the DNS credential test writes `_acme-challenge._certforge-test.<zone>` (lego always prepends `_acme-challenge.`).
- 1B: fixed from Task 10's re-review — `FinishAttempt` only updates a row still `outcome = 'running'`, so a second finish (for example a panic recovery racing the worker's own error path) cannot overwrite a previously recorded outcome; the store now discards the `:execrows` row count since a no-op finish is not an error.
- 1B: `api.Deps` gains `Issuance *issuance.Service`, wired in `serve.go` from the same `Store`/`certstore.Store`/river client the scheduler uses, so Tasks 12–14 build handlers directly on it. River's client is started with `context.Background()`, not the process's signal context, because cancelling the context passed to `Start` aborts running jobs immediately; graceful draining is `stopRiver`'s job (30 s `Stop`, then a 10 s `StopAndCancel`). `IssueWorker.Log` is now set to the server's configured logger instead of defaulting to `slog.Default()`.
- 1B: API shapes follow plan 1C: CAs, accounts, credentials, versions, attempts and manual-dns records are plain arrays; only certificates page with `{items, nextCursor}` (offset cursor, filtered and sorted in memory at Phase 1 scale). Effective values report `source` `default` for built-ins.
- 1B Task 12: `api.Deps` also gains `Certs *certstore.Store` (Task 14 downloads read certificate versions directly, without a second facade). `(*issuance.Store).DeleteCA` and `DeleteAccount` run their count-then-delete inside one transaction that locks the parent row (`SELECT ... FOR UPDATE`, new `LockCA`/`LockAccount` queries) first. CA create/update/delete and ACME account create/delete are audited (`ca.create`/`update`/`delete`, `acme_account.create`/`delete`); org issuance-defaults writes are audited as `issuance_defaults.update`; the global section's write was already audited as `settings.update` by 1A and needed no new event.
- 1B Task 12: fix round 1 — the initial `FOR UPDATE` lock only conflicted with `acme_accounts` inserts through their foreign key; a writer that stores a `caId`/`accountId` reference in jsonb (org issuance defaults, the global `issuance_defaults` section) read the referenced row without taking any lock, so a concurrent `PutOrgDefaults` or global-section write could still commit a dangling reference while a delete was mid-transaction. New `LockCAKeyShare`/`LockAccountKeyShare` queries (`SELECT id FROM ... WHERE id = $1 FOR KEY SHARE`, a lock that conflicts with `FOR UPDATE` but not with plain reads) are now taken by `validateDefaultsTx` (used by `PutOrgDefaults`) and `ValidateGlobalDefaultsTx` (used by the settings write path, replacing the non-transactional `ValidateGlobalDefaults` there — that method stays for its own existing tests) before checking existence, so `DeleteCA`/`DeleteAccount`'s `FOR UPDATE` now blocks until a concurrent org- or global-defaults write finishes, and vice versa; whichever finishes first, the other's read is guaranteed to see it. `DeleteCA`/`DeleteAccount`'s `globalDefaultsReference` check now also runs inside their own transaction (`globalDefaultsReferenceTx`), through a new `(*settings.Store).GetTx`/`PutSectionTx` pair the `GlobalSettings` interface picks up via an optional `txGlobalSettings` type assertion (test doubles that only implement the plain `Get` still work, falling back to it). `PUT /settings/issuance_defaults` now begins its own transaction, takes the locks, and writes the section through `PutSectionTx` in the same transaction, committing only once both succeed. Certificate overrides (Task 14) have the same jsonb-reference gap and are explicitly out of scope here — Task 14 should reuse `validateDefaultsTx`'s pattern (or equivalent) when it wires `CreateCertificate`/`UpdateCertificate` to the API; Task 13's DNS credential delete should also take a matching key-share lock when it stores/reads `dnsCredentialId` references. Also fixed: the section's JSON Schema `format: uuid` is an annotation only (not asserted by the compiler), so a syntactically malformed `caId` passed schema validation and previously surfaced as 400 from the subsequent Go `json.Unmarshal`; that path now returns 422 (`unprocessable`) like every other validation failure on the section. New integration test `TestDeleteCaLockBlocksConcurrentOrgDefaultsWrite` holds a CA's `FOR UPDATE` lock open in one goroutine, proves a concurrent `PutOrgDefaults` referencing that CA blocks (via a timeout), then commits a delete through the held transaction and proves the blocked write wakes up with a 422 instead of succeeding.

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
- 1B: lego v4 is not context-aware on its own; the ACME signer wraps its HTTP transport to check the issuance context before every request and attach it to each one, so cancellation now aborts an in-flight CA call (not just manual-dns waits). lego's internal nonce-retry backoff sleeps (bounded at 20s, only on nonce invalidation) are not ctx-aware.
- 1B: lego's log output is process-global and is not copied into attempt logs; attempts log CertForge's own steps and errors.
- 1B: no `cert.issued` event is emitted yet; notifiers, deploy targets, Vault sync and agent nudges (Phases 3, 5, 6) add it. "Notify on 3rd failure" arrives with notifiers (Phase 6).
- OpenAPI component schemas use DNSCredential, DNSCredentialInput, DNSCredentialTestResult (DNS casing); plan 1C's api/types.ts must use these names.
