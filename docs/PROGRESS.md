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

### Phase 1B: issuance engine — done (started 2026-09-24, finished 2026-09-24) ([plan](superpowers/plans/2026-09-24-phase-1b-issuance-engine.md))

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
| 13 | API: DNS credentials | done | 5ab8e5d |
| 14 | API: certificates, versions, attempts, downloads, manual-dns | done | 4fa1db3 |
| 15 | Pebble end-to-end test | done | 15085f8 |

Phase 1B complete; 1C (web UI) builds on it. Task 15's row records 15085f8,
the 1B final-review fix commit that closed out Phase 1B (lost-name races in
the issuance worker, a per-name propagation budget in the challenge router,
the provider-default propagation timeout, and the DNS credential
secret-reuse guard, among smaller fixes — see the Decisions entry below);
13ca4cd and f42b3ef were Task 15's own commits.

### Phase 1C: web UI — in progress (started 2026-09-24) ([plan](superpowers/plans/2026-09-24-phase-1c-web-ui.md))

| # | Task | Status | Commit |
|---|---|---|---|
| 1 | Scaffold, tokens, fonts, theme, lint | done | 07f60a1 |
| 2 | API client and query plumbing | done | pending |
| 3 | Router, login, setup wizard | planned | |
| 4 | App shell and navigation | planned | |
| 5 | Form controls | planned | |
| 6 | Status chip and validity bar | planned | |
| 7 | Issuers: CAs and ACME accounts | planned | |
| 8 | SchemaForm and provider picker | planned | |
| 9 | DNS credentials | planned | |
| 10 | InheritableField and Settings | planned | |
| 11 | Certificates list | planned | |
| 12 | Wizard names step | planned | |
| 13 | Verification rules and coverage | planned | |
| 14 | Wizard assembly | planned | |
| 15 | Attempts and manual DNS | planned | |
| 16 | Certificate detail | planned | |
| 17 | Overview and command palette | planned | |
| 18 | Docker build, Playwright smoke, docs | planned | |

## Decisions made during implementation

- CF_LOG_LEVEL is read from the environment in addition to the spec's bootstrap list, because the log level is needed before the database is reachable.
- bootstrap-admin reads CF_ADMIN_PASSWORD as one-shot CLI input; it is not server configuration and serve never reads it.
- LoadPrincipal ignores site-scoped role bindings (non-NULL site_id): they contribute nothing to a principal until site scope is modelled in Phase 2.
- The router has a local recoverer (panics become problem+json 500s, not bare ones) and the root NotFound/MethodNotAllowed handlers return problem+json for any `/api/*` path.
- Outside `/api/*`, the root NotFound handler serves the embedded SPA's index.html for any unmatched path, so client-side routes resolve without a route list in the Go router.
- Login and setup-complete build the full principal before starting the session; the cf_session cookie is set only once every step has succeeded, and a partially-failed login/setup deletes the session row it created.
- setup.Service.Complete validates baseUrl against the general settings section's JSON Schema (the same schema PUT /settings/general enforces) in addition to config.ValidateBaseURL, and short-circuits with ErrAlreadyComplete as soon as setup is already done.
- `make e2e` runs under the isolated compose project `certforge-e2e` (not the dev stack's `certforge` project), with host ports overridable via CF_HTTP_PORT, CF_AGENT_PORT, and CF_PEBBLE_MGMT_PORT.
- Pebble's management port is published to the host in `deploy/compose.test.yaml` (`CF_PEBBLE_MGMT_PORT` default 15000), not just reachable over the compose network, so the issuance e2e (a host-side `go test` process that otherwise only talks to the compose server's own HTTP API) can independently verify the issued chain against `:15000/intermediates/0` and `:15000/roots/0`. Pebble's ACME port and challtestsrv's ports are not published: only the compose server itself calls them, over the compose network — see docs/development.md.
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
- 1B: API shapes follow plan 1C: CAs, accounts, credentials, versions, attempts and manual-dns records are plain arrays; only certificates page with `{items, nextCursor}` (a real keyset cursor over `sort`/`q`/`status`-filtered SQL, replaced from an earlier in-memory offset cursor by Task 14's fix round 1 — see its entry below). Effective values report `source` `default` for built-ins.
- 1B Task 12: `api.Deps` also gains `Certs *certstore.Store` (Task 14 downloads read certificate versions directly, without a second facade). `(*issuance.Store).DeleteCA` and `DeleteAccount` run their count-then-delete inside one transaction that locks the parent row (`SELECT ... FOR UPDATE`, new `LockCA`/`LockAccount` queries) first. CA create/update/delete and ACME account create/delete are audited (`ca.create`/`update`/`delete`, `acme_account.create`/`delete`); org issuance-defaults writes are audited as `issuance_defaults.update`; the global section's write was already audited as `settings.update` by 1A and needed no new event.
- 1B Task 12: fix round 1 — the initial `FOR UPDATE` lock only conflicted with `acme_accounts` inserts through their foreign key; a writer that stores a `caId`/`accountId` reference in jsonb (org issuance defaults, the global `issuance_defaults` section) read the referenced row without taking any lock, so a concurrent `PutOrgDefaults` or global-section write could still commit a dangling reference while a delete was mid-transaction. New `LockCAKeyShare`/`LockAccountKeyShare` queries (`SELECT id FROM ... WHERE id = $1 FOR KEY SHARE`, a lock that conflicts with `FOR UPDATE` but not with plain reads) are now taken by `validateDefaultsTx` (used by `PutOrgDefaults`) and `ValidateGlobalDefaultsTx` (used by the settings write path, replacing the non-transactional `ValidateGlobalDefaults` there — that method stays for its own existing tests) before checking existence, so `DeleteCA`/`DeleteAccount`'s `FOR UPDATE` now blocks until a concurrent org- or global-defaults write finishes, and vice versa; whichever finishes first, the other's read is guaranteed to see it. `DeleteCA`/`DeleteAccount`'s `globalDefaultsReference` check now also runs inside their own transaction (`globalDefaultsReferenceTx`), through a new `(*settings.Store).GetTx`/`PutSectionTx` pair the `GlobalSettings` interface picks up via an optional `txGlobalSettings` type assertion (test doubles that only implement the plain `Get` still work, falling back to it). `PUT /settings/issuance_defaults` now begins its own transaction, takes the locks, and writes the section through `PutSectionTx` in the same transaction, committing only once both succeed. Certificate overrides (Task 14) have the same jsonb-reference gap and are explicitly out of scope here — Task 14 should reuse `validateDefaultsTx`'s pattern (or equivalent) when it wires `CreateCertificate`/`UpdateCertificate` to the API; Task 13's DNS credential delete should also take a matching key-share lock when it stores/reads `dnsCredentialId` references. Also fixed: the section's JSON Schema `format: uuid` is an annotation only (not asserted by the compiler), so a syntactically malformed `caId` passed schema validation and previously surfaced as 400 from the subsequent Go `json.Unmarshal`; that path now returns 422 (`unprocessable`) like every other validation failure on the section. New integration test `TestDeleteCaLockBlocksConcurrentOrgDefaultsWrite` holds a CA's `FOR UPDATE` lock open in one goroutine, proves a concurrent `PutOrgDefaults` referencing that CA blocks (via a timeout), then commits a delete through the held transaction and proves the blocked write wakes up with a 422 instead of succeeding.
- 1B Task 14: `CreateCertificate`/`UpdateCertificate` now follow `PutOrgDefaults`'s pattern (Task 12's fix round 1): both run in one transaction and validate through `prepareCertTx` → `validateDefaultsTx`/`validateRulesOrgTx`, taking `LockCAKeyShare`/`LockAccountKeyShare`/`LockDNSCredentialKeyShare` on every CA, account and DNS credential a certificate's overrides or rules reference before checking it exists, so a concurrent `DeleteCA`/`DeleteAccount`/`DeleteDNSCredential` blocks until the certificate write's transaction ends. The pool-bound `validateDefaults`/`validateRulesOrg` this replaced had no other callers and were removed rather than left dead. `ListCertificates` avoids the N+1 a naive per-item `certOut` would cause (2-3 queries per certificate — `EffectiveFor` re-reads global and org defaults every time, plus a `CertificateVersion` lookup): it now loads global and org defaults once for the whole page (identical for every certificate of one org) and batch-loads every matched certificate's current version in one query (new `certstore.Store.Versions`, backed by `ListCertificateVersionsByIDs ... WHERE id = ANY($1::uuid[])`), so the handler issues a constant number of queries regardless of page size. `render.ErrNoKey` (a version with no stored key) maps to 404, never 500.
- 1B Task 14 fix round 1 (review): the list endpoint's pagination is now a real keyset cursor, not the offset cursor over an in-memory sort described above — that offset scheme skipped or repeated rows when a certificate was inserted or deleted between page fetches, and its cursor wasn't bound to the request's own `sort`/`q`/`status`, so replaying it with different filters silently resumed from the wrong place. `(*issuance.Store).ListCertificatesPage` now runs one of 8 new sqlc queries (`ListCertificatesPageBy{Name,Status,NextRenewAt,NotAfter}{Asc,Desc}`), each filtering by `status`/`q` in SQL (`q` is a case-insensitive substring of the name, common name, or any SAN, matching the old in-memory `listParams.matches`) and resuming with `WHERE (sortKey, id) > (lastKey, lastId)` (or `<` descending), fetching `limit+1` rows to detect `nextCursor` without a second round trip. A nullable sort column (`next_renew_at`, and `not_after` via a `LEFT JOIN certificate_versions`, both null for a certificate with no current version) is `COALESCE`d to the X.509 "no well-defined expiration" sentinel `9999-12-31T23:59:59Z` rather than compared directly, since Postgres row comparison against a `NULL` silently excludes every row instead of raising an error; the sentinel also reproduces Postgres's own `NULLS LAST` ascending / `NULLS FIRST` descending defaults without special-casing either direction. `api/certificates.go`'s `nextCursor` is now `base64url({sort, desc, q, status, lastKey, lastId})`; `decodeCertCursor` 422s a cursor that fails to decode *or* whose bound `status`/`q`/`sort`/`desc` differ from the current request, so a tampered or merely stale cursor can't silently resume in the wrong ordering. `UpdateCertificate` now reads the current row with a new `GetCertificateForUpdate` (`FOR UPDATE`) query inside its transaction, so a concurrent update can't compute `reissue` from names that are already stale by commit time. `Service.CreateCertificate`/`UpdateCertificate` now audit (`certificate.create`/`update`, moved out of the API handlers and into the Service itself, gaining `Auditor *audit.Auditor` and `Log *slog.Logger` fields) immediately after the store transaction commits and *before* `EnqueueIssue`, and a failed enqueue is logged and swallowed rather than turned into a 500 for a certificate that, by that point, has already been durably written; the periodic scheduler picks up any certificate an enqueue failed for within `SchedulePeriod` regardless. `Timeline`'s log is now capped at 64 KiB (oldest lines dropped first, a single `[log truncated]` marker prepended once truncation happens) and a recovered panic's stack trace is capped at 4 KiB before being logged, so neither a chatty provider, an hour-long manual-dns poll loop, nor a deep panic stack can grow `issuance_attempts.log` without bound.
- OpenAPI schema names use DNS casing throughout (`ManualDNSRecord`, `ManualDNSConfirmResult`, `DNSCredential*`); plan 1C's `api/types.ts` must use these names. `DeleteCertificate` needs no explicit job-cancel step: the migration already cascades `certificate_versions`/`issuance_attempts`/`manual_pending` off the certificate row, and `IssueWorker.Issue` already treats a deleted certificate as a no-op (`return nil` on `ErrNotFound`) for a job that was still queued. Certificate create/update/delete, renew, and manual-dns confirm are now audited (`certificate.create`/`update`/`delete`/`renew`/`manual_dns_confirmed`); `certificate.key_exported` on a key/combined download is recorded with a blocking `Auditor.Record` call (not the fire-and-forget `s.audit` helper), so an audit failure returns a plain 500 and releases no key material. OperationIds use DNS casing (`listManualDNS`, `confirmManualDNS`), matching Task 13's `DNSCredential` naming; schema names `ManualDNSRecord`/`ManualDNSConfirmResult` follow the same casing for consistency, though only operationIds were a binding requirement.
- 1B Task 15: the issuance e2e (`test/e2e/issuance_test.go`) drives the *running compose server* through its HTTP API, not the issuance engine in process, per the controller ruling that the compose e2e must exercise the server's own HTTP surface. See docs/development.md's "Tests" section and the ports table above it for what it does and which ports `deploy/compose.test.yaml` publishes.
- 1B final-review fix wave: `IssueWorker.succeed` re-reads the certificate row inside `MarkCertificateIssued`'s own `UPDATE ... RETURNING next_renew_at` (a `CASE` comparing the row's current `common_name`/`sans` against the names this attempt actually issued for, both passed as query parameters — no separate `FOR UPDATE` read, so there's no window for a concurrent name change to race the comparison); if they differ (an operator changed the certificate's names while the attempt was running), `next_renew_at` stays `now()` instead of the normal renewal date, so the scheduler reissues for the new names within its next sweep instead of silently losing the edit for the certificate's whole lifetime — the parallel `UpdateCertificate`-triggered enqueue for the new names is a no-op duplicate against the job already running for the old ones (`IssueArgs.InsertOpts`'s `UniqueOpts`).
- 1B final-review fix wave: `internal/challenge/router.go` now enforces a *per-name* propagation budget in `PreCheck` (`ruleTimeout`, started once a name is past any manual-dns wait), independent of `Router.Timeout`'s single order-wide value — previously a `dns-01` name sharing a certificate with a long `manual-dns` wait was polled by lego for just as long as that wait, since `Timeout()` returns one value for the whole order (the largest rule in use). A budget expiring, or a CNAME `cnameAliasZone` mismatch, now fails fast (`markFailed`, report ready) the same way a manual-dns timeout already did, instead of returning a bare error `dns01.Solve`'s `wait.For` would just keep retrying against. `Router.Timeout` only adds a manual rule's `WaitBudget` for a name whose Waiter has not yet returned, so it shrinks once the operator confirms instead of still allowing the full (already-spent) wait on top of the propagation timeout.
- 1B final-review fix wave: the built-in `propagationSeconds` default (`issuance.BuiltinDefaults`) is now unset (0, the router's existing "provider default" sentinel) instead of a fixed 120s — a fixed built-in value always won over a rule's own `rule.Provider.Timeout()`, so a DNS credential's own `*_PROPAGATION_TIMEOUT` config could never take effect unless every level of defaults was left unset *and* the built-in happened to already be 0.
- 1B final-review fix wave: `challenge.MergeUpdate` (DNS credential update) now also reports which public config keys the update changed and whether any secret field was sent as `__unchanged__`; `issuance.Store.UpdateDNSCredential` rejects (422) an update that does both at once — otherwise an operator could repoint a stored secret at a changed connection setting (for example a provider's endpoint URL) without ever re-entering it. The `dns_credential.update` audit event now lists the changed public keys (`changedConfig`).
- 1B final-review fix wave, smaller items: the panic-recovery path in `IssueWorker.Issue` now applies `MarkFailed` with the normal backoff (it previously only recorded the attempt as failed, leaving the certificate's `failure_count`/`next_renew_at` untouched); `succeed`'s own timeline saves route through its open transaction (not the store's connection pool, which could deadlock a small pool against the row lock `succeed` already holds) and every attempt-progress save now has a 5s bound; `UpdateCA` rejects (409) a `directoryUrl` change while an ACME account is still registered against the CA (its key is enrolled with the old server); `deploy/compose.test.yaml`'s e2e build now tags its image `certforge:e2e`, distinct from `compose.yaml`'s `ghcr.io/metril/certforge:dev`, so a dev `up` can never end up running the e2e-only provider; the schema generator marks `INFOBLOX_CA_CERTIFICATE` (a path field whose name doesn't follow the `_FILE`/`_PATH` convention) `serverPath` and `hyperone` (file-only passport) `unsupported`, like `transip`.
- 1C: theme pre-paint runs from a synchronous `/theme-init.js` in `<head>` instead of an inline script, so a `script-src 'self'` CSP holds; behaviour is identical.
- 1C: routes use a pathless `_app` layout (auth guard + shell) and nested `o/$org/` folders; URLs match the spec. Task 1 adds a placeholder `src/routes/__root.tsx` only so the TanStack Router Vite plugin (which scans `src/routes` at config-resolve time) has something to generate against before Task 3 builds the real router.
- 1C: status chip words use `ink`; the tone is carried by icon, border, or fill, because `expiring` on white is 3.6:1 (below AA for text).
- 1C: `@tanstack/react-table` pinned to 8.21.3 (9.x is a fresh major).
- 1C: tooltip "Learn more" links resolve against `VITE_DOCS_BASE` (default `https://github.com/metril/certforge/blob/main/docs/`).
- 1C: the CA edit sheet is addressed by `?edit=<id>` on `/issuers/cas` rather than a `/:id` segment.
- 1C: certificate create sends `sans` including the common name.
- 1C Task 1: the Vite dev proxy's default backend is `http://localhost:${CF_HTTP_PORT:-8080}` (not a bare `:8080`), since `CF_HTTP_PORT` is already how `make e2e`/compose pick a non-default host port and this host runs the dev API on 18080.
- 1C Task 1: `shadcn@4.21.0 add` generates components importing `cn` from a package literally named `cn` rather than `@/lib/utils`, and adds that package to `package.json`; both are reverted (`sed` the imports back to `@/lib/utils`, drop the `cn` dependency) to keep the exact-pinned dependency set and a single `cn` implementation.
- 1C Task 1: `src/test/setup.ts`'s jsdom shims (`Element.prototype.*`, `window.matchMedia`, `localStorage.clear()`) are guarded with `typeof ... !== 'undefined'` checks, because `setupFiles` also runs for `lint.test.ts` and `tokens.test.ts`, which opt into `@vitest-environment node` and have no DOM globals.
- 1C Task 1: `tsconfig.app.json`'s `types` also lists `"node"` (the brief omitted it), since the tests import `node:fs`/`node:path` and read `import.meta.dirname`, an `@types/node` global augmentation that needs `types` to include it explicitly.
- 1C Task 1: `public/theme-init.js`'s `var dark` has no initializer (ESLint's `no-useless-assignment` flags `= false` as dead, since every path — the try block or the catch — always assigns it before use).
- 1C Task 2: `types.ts` aliases the real component names, which use DNS/ManualDNS casing (`DNSCredential`, `DNSCredentialInput`, `ManualDNSRecord`, plus `DNSCredentialUpdate` and `DNSCredentialTestResult` for later tasks), not the `DnsCredential`/`ManualDnsRecord` casing the brief assumed; the exported alias names are unchanged. `EffectiveValue`/`EffectiveMap` and `Source` incl. `'cert'` are dropped in favor of aliasing the API's own `EffectiveIssuanceDefaults`/`Source`, which already carry a `{value, source}` shape per field — no hand-rolled casts needed.
- 1C Task 2: the API declares no non-2xx responses, so every error is treated as RFC 9457 problem+json; `ApiError` also carries an optional `retryAfter` (seconds), parsed from a 503's `Retry-After` header (integer-seconds or HTTP-date form), and `errorMessage` appends "Retry in Ns." when set.
- 1C Task 2: `authMiddleware` clones a mutating request's body before it is sent (`Request.clone()`, stashed in a `WeakMap`) so a CSRF-flavoured 403 (a valid session whose cached token went stale — `authn.Middleware` 403s any mutating request with a bad or missing token) can refresh `/auth/me` and retry exactly once, guarded by a `WeakSet` against looping if the retry is also rejected.
- 1C Task 2: the default `setUnauthorizedHandler` performs a full-page navigation to `/login?next=<path>` on an unexpected 401 rather than an SPA route push; that also clears every in-memory cache (React Query's `me` included), so no separate query-cache clear is needed. Router-aware tasks may still call `setUnauthorizedHandler` to override it.
- 1C Task 2: `make generate` now also runs `npm --prefix web run gen` (guarded by `[ -d web ]`) so the CI drift check covers `web/src/api/schema.d.ts`.

## Known gaps

- 1B: revocation is implemented in `signer.Signer` but not exposed in the API (the Revoke action lands with its screen).
- Pebble and challtestsrv images are pinned to tag 2.10.1, not a digest; the issuance e2e (1B Task 15) kept the tag pin rather than switching to a digest. Pin digests in a later task.
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
- A DNS provider whose only lego credential input is a server-side file (no inline field exists) is marked `unsupported: true` in its schema (`GET /meta/schemas` still lists it) and rejected with 422 on create/update; `transip` and `hyperone` are the only ones so far. Not offered until file-backed credentials arrive in Phase 5.
- The scheduler still enqueues issuance jobs when the KEK canary has failed; it should refuse to schedule work it cannot decrypt/seal material for.
- DNS provider secrets sit in the process environment during a lego provider's `Build` (lego's own env-var-based construction); no isolation beyond that yet.
- River's own health (queue depth, stuck jobs) is not part of `/readyz`; only the database and KEK canary are checked.
- Providers with ambient cloud credentials (`route53`, `gcloud`, `azuredns`, …) fall back to the server's own identity (instance role, ADC, …) when no keys are set on the stored credential; nothing here gates that off from a CertForge deployment's own cloud identity. Gate this in Phase 2.
- A database error inside `IssueWorker.succeed` (after the CA has already issued) makes river retry the whole issuance from scratch, including a fresh CA order — against Let's Encrypt this risks the duplicate-certificate rate limit on a flaky database.
- `MaxWorkers=4` is shared by every river job kind, including the periodic scan job and hour-long manual-dns waits; a burst of manual-dns issuances can starve renewals.
- 1C: Overview "recent activity" needs the audit log (Phase 2).
- 1C: Revoke action needs a revoke endpoint; Deployments tab is Phase 3.
