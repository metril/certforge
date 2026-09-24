# CertForge progress

Single status file. Updated in every commit that completes a task.

## Phases

| # | Phase | Status | Spec | Plan | Started | Finished |
|---|---|---|---|---|---|---|
| 1 | Core issuance slice | in progress | [design](design.md) | [1A](plans/2026-09-24-phase-1a-backend-foundation.md) | 2026-09-24 | – |
| 2 | Identity and tenancy | planned | [design](design.md) | – | – | – |
| 3 | Agent | planned | [design](design.md) | – | – | – |
| 4 | Issuance breadth and formats | planned | [design](design.md) | – | – | – |
| 5 | Vault and private CA | planned | [design](design.md) | – | – | – |
| 6 | Ops | planned | [design](design.md) | – | – | – |
| 7 | Deploy targets | planned | [design](design.md) | – | – | – |

## Active phase tasks

Phase 1 is split into three plans: 1A backend foundation, 1B issuance, 1C web UI.

### Phase 1A: backend foundation ([plan](plans/2026-09-24-phase-1a-backend-foundation.md))

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
| 12 | Health, web UI placeholder, serve | done | pending |
| 13 | Container image and compose | todo | – |
| 14 | Architecture docs and phase close-out | todo | – |

## Decisions made during implementation

- CF_LOG_LEVEL is read from the environment in addition to the spec's bootstrap list, because the log level is needed before the database is reachable.
- bootstrap-admin reads CF_ADMIN_PASSWORD as one-shot CLI input; it is not server configuration and serve never reads it.

## Known gaps

- Audit log tamper-evidence hardening not yet done: keyed HMAC instead of a plain hash, anchoring the head hash outside the table, and running the app under a role that does not own `audit_events`.
- Login attempts are not rate limited yet (argon2id cost only); add per-IP throttling with the Phase 2 auth work.
- Settings sections cannot hold secret fields yet; add write-only secret: true support when the first secret-bearing section lands (Phase 2 OIDC).
