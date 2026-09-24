# Changelog

All notable changes to CertForge are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Design specification, progress tracker, and repository scaffolding.
- Go module, certforge command skeleton, Makefile, golangci-lint config, CI workflow, development guide, ADRs 0001 and 0003.
- Bootstrap configuration from CF_* environment variables with KEK from env or file.
- Postgres pool, embedded goose migrations (orgs, sites, users, sessions, role bindings, settings, audit events), sqlc code generation, migrate command.
- Envelope encryption (AES-256-GCM DEK per secret, static KEK wrapper) with a compact blob format.
- Settings store with encrypted secrets, JSON-Schema-validated sections (general, backup), and KEK canary.
- Local admin argon2id passwords, Postgres-backed sessions, CSRF enforcement, and request principal middleware.
- Role-based authorization with org-scoped bindings (authz.Can).
- Append-only, hash-chained audit log with chain verification.
- OpenAPI spec with generated strict server, problem+json errors, Swagger UI at /api/docs, meta schema registry, org listing.
- Local admin login, logout, /auth/me with CSRF token, and schema-driven settings GET/PUT endpoints.
- First-run setup endpoints (status, complete) and the bootstrap-admin command.
- serve and healthcheck commands, /healthz and /readyz (DB and KEK canary), embedded web UI handler with SPA fallback and placeholder page.
- Server container image, compose stack with Postgres 16, test overlay with Pebble and challtestsrv, e2e health test.
- Architecture overview and documentation index.
- Issuance database schema: CAs, ACME accounts, DNS credentials, org issuance defaults, certificates, versions, attempts, manual-dns records.
- Routing challenge provider: per-name verification rules (`*`, `*.zone`, `zone`), first match wins, uncovered names rejected before ordering.
- JSON Schemas for all lego DNS providers, generated from lego's metadata, served under `dnsProviders` in `GET /api/v1/meta/schemas`, and documented in `docs/dns-providers.md`.
- DNS credential handling: schema-validated config, write-only secrets with the `__unchanged__` sentinel, and lego provider construction with an isolated environment.
- manual-dns verification: TXT records shown to the operator, attempt resumes on confirmation, fails after 1 hour without it.
- ACME signer on lego v4 with CA presets (Let's Encrypt, staging, ZeroSSL, Buypass, Google Trust Services, SSL.com, custom), EAB registration and Retry-After capture. Cancelling the issuance context now aborts an in-flight CA call promptly, not just manual-dns waits.
- PEM rendering of cert, chain, fullchain, key and combined parts, with deterministic zip bundles.
- Issuance defaults at global, org and certificate level with per-field source, renewal policy (days or percent), and exponential backoff honouring Retry-After.
- Issuance data layer with org scoping, sealed EAB HMACs, account keys and DNS secrets, and delete protection for referenced CAs, accounts and credentials.
- Issue worker: per-attempt step timeline, sealed certificate versions, next renewal from policy, failure backoff with Retry-After.
- Renewal scheduler: river periodic scan every 5 minutes, one unique issue job per certificate, expiry marking and stale-attempt cleanup.
- Issuance service facade (account registration, certificate create/update with auto-enqueue, DNS credential test) and `serve` wiring: river client started and gracefully stopped alongside the HTTP server, `db.Migrate` now also applies river's schema.
- API: CA presets, CAs with EAB, ACME account registration, org issuance defaults and effective defaults with sources.

### Fixed
- Deleting a CA or ACME account locks the row for the whole count-then-delete in one transaction, so a concurrent `acme_accounts` insert (an actual foreign key) cannot slip a new reference in between the check and the delete.
- Closed the remaining half of that race: writers that store a `caId`/`accountId` reference in jsonb instead of a foreign key (org issuance defaults, the global `issuance_defaults` section) now take a `FOR KEY SHARE` lock on the referenced row before validating and writing, so a CA/account delete's `FOR UPDATE` lock blocks them (and they block it) until one side finishes; a delete's own "is this still referenced" checks now also run inside its own transaction. `PUT /settings/issuance_defaults` validates the global section with the new transactional `(*issuance.Store).ValidateGlobalDefaultsTx` (referenced CA/account/DNS credential rows must exist) and writes it through the same transaction, not just against its JSON Schema.
- A syntactically malformed `caId`/`accountId` in `PUT /settings/issuance_defaults` (the section schema's `format: uuid` is an annotation, not an enforced assertion) now returns 422 like every other invalid value on the section, not 400.
- `NextRenewAt`'s percent-mode renewal calculation no longer overflows for a very large certificate lifetime; a step returning to a non-terminal status no longer keeps a stale `FinishedAt`; a `Timeline` save now runs while the lock is held so concurrent updates can't land out of order; the `issuance_defaults` settings schema now caps `renewPolicy.value` at 99 in percent mode; DNS credential config errors are classified by error type, not by matching substrings; writes to global or org issuance defaults now verify that a referenced CA, ACME account or DNS credential row actually exists, and deleting one now also checks the global defaults section.
- `FinishAttempt` now only closes an attempt still `outcome = 'running'`, so a second finish call (for example a panic recovery racing the worker's normal error path) cannot silently overwrite an already-recorded outcome.
- Final review fixes: published Pebble e2e ports, closed a setup/bootstrap-admin takeover gap (bootstrap-admin now refuses before setup completes; Complete revokes a pre-existing admin's sessions), added resource-exhaustion limits on public auth routes (body size, password length, argon2 concurrency, server timeouts), made the KEK canary write insert-if-absent, made audit-write failures log-and-continue, and corrected several doc inaccuracies.
- Argon2 timing-equalizer hash no longer contends for the argon2 concurrency semaphore, so it cannot be permanently disabled by a saturated first call; the semaphore's release closure now captures the channel it acquired instead of the package variable; the KEK canary write is now insert-or-fill, treating a `crypto.canary` row with a NULL secret as absent; `bootstrap-admin` docs and help text now say "reset (after setup)" instead of "create or reset".
