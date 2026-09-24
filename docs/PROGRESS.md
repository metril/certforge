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
| 6 | Local admin auth, sessions, CSRF | done | pending |
| 7 | Authorization | todo | – |
| 8 | Audit log | todo | – |
| 9 | OpenAPI skeleton, router, problem+json | todo | – |
| 10 | Auth and settings endpoints | todo | – |
| 11 | Setup wizard and bootstrap-admin | todo | – |
| 12 | Health, web UI placeholder, serve | todo | – |
| 13 | Container image and compose | todo | – |
| 14 | Architecture docs and phase close-out | todo | – |

## Decisions made during implementation

- CF_LOG_LEVEL is read from the environment in addition to the spec's bootstrap list, because the log level is needed before the database is reachable.

## Known gaps

None yet.
