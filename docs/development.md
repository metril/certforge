# Development

## Prerequisites

- Go 1.23
- Docker: integration tests use testcontainers, e2e uses compose
- A C compiler (gcc or clang): `make generate` builds sqlc, which needs cgo
- GNU make and curl

`make` targets set `GOTOOLCHAIN=local` (CI does too) so a pinned dependency never triggers an automatic toolchain download; run `go` commands with it set the same way when working outside `make`.

## Repository layout

| Path | Contents |
|---|---|
| `api/openapi.yaml` | API source of truth. Go server stubs (and later the TS client) are generated from it |
| `cmd/certforge/` | Server binary: `serve`, `migrate`, `bootstrap-admin`, `healthcheck`, `version` |
| `internal/config/` | Bootstrap env config |
| `internal/db/` | pgx pool, embedded goose migrations, sqlc queries, generated `sqlcgen/`, `dbtest/` test helper |
| `internal/crypto/` | Envelope encryption and `KeyWrapper` |
| `internal/settings/` | Settings store, encrypted secrets, schema-validated sections |
| `internal/authn/`, `internal/authz/` | Sessions, CSRF, principal; roles and `Can()` |
| `internal/audit/` | Hash-chained, append-only audit log |
| `internal/api/` | Router, handlers, problem+json, generated server in `gen/` |
| `internal/meta/` | Registry of pluggable type schemas |
| `internal/setup/` | First-run wizard and `bootstrap-admin` |
| `internal/webui/` | Embedded web UI with SPA fallback |
| `cmd/certforge-agent/` | Agent binary |
| `internal/agent/` | Agent enrolment, client, reconcile, targets, hooks |
| `internal/agentproto/` | Wire protocol shared by server and agent |
| `internal/agentca/` | Agent CA and listener certificate |
| `internal/agents/` | Server-side agents service |
| `internal/agenthub/` | Agent WebSocket registry |
| `internal/delivery/` | Layouts, Traefik rendering, digests |
| `deploy/` | Dockerfile and compose files |
| `test/e2e/` | Compose-driven end-to-end tests |

## Make targets

| Target | What it does |
|---|---|
| `make generate` | Runs sqlc and oapi-codegen at pinned versions |
| `make build` | Builds `bin/certforge` with the placeholder web page, and `bin/certforge-agent` |
| `make build-embed` | Copies `web/dist` into `internal/webui/dist` and builds with `-tags embedweb` |
| `make image-agent` | Builds the agent image (`deploy/Dockerfile.agent`) as `ghcr.io/metril/certforge-agent:dev` |
| `make test` | Unit tests with `-race` |
| `make test-integration` | Unit and integration tests (`-tags integration`, needs Docker) |
| `make lint` | golangci-lint v1.61.0 with `.golangci.yml` |
| `make e2e` | Starts `deploy/compose.yaml` + `deploy/compose.test.yaml`, runs `-tags e2e` tests, then tears down |
| `make vendor-swagger` | Downloads the pinned swagger-ui files into `internal/api/docs/` |

`make e2e` runs the stack under the `certforge-e2e` compose project (separate
from a `docker compose -f deploy/compose.yaml up` dev stack, so `down -v`
never touches the dev stack's `certforge_pgdata` volume). Its host ports are
overridable, useful when the defaults are already taken:

| Variable | Default | Port |
|---|---|---|
| `CF_HTTP_PORT` | `8080` | certforge HTTP (also sets `CF_E2E_BASE_URL` and the default `CF_BASE_URL`) |
| `CF_AGENT_PORT` | `8443` | certforge agent listener |
| `CF_PEBBLE_MGMT_PORT` | `15000` | Pebble management API (also sets `CF_E2E_PEBBLE_MGMT`; the issuance e2e independently verifies the issued chain against `/intermediates/0` here) |
| `CF_DEX_PORT` | `5556` | dex (e2e OIDC provider; also sets `CF_E2E_DEX_ADDR`). Playwright maps the name `dex` to `127.0.0.1`, so keep `5556` when running the browser test. |

The issuance e2e test drives the compose server through its own HTTP API
(`CF_E2E_BASE_URL`), the same way a real client would; it never talks to
Pebble or challtestsrv directly — only the compose server does, over the
compose network (`pebble:14000`, `challtestsrv:8055`/`:8053`). Pebble's
management port is the one exception, published to the host so the test can
independently check the chain it got back through the API against Pebble's
own roots/intermediates. Example: `CF_HTTP_PORT=18080 make e2e`.

The same stack and the same `CF_HTTP_PORT` override are used by the browser
smoke test below (`web/e2e/`); it just drives the running server with a real
browser instead of `go test`.

## Code generation

Generated code is committed. CI runs `make generate && git diff --exit-code`, so always regenerate and commit together.

- **SQL:** add a `-- name: X :one|:many|:exec|:execrows` query to a file in `internal/db/queries/`, then run `make generate`. Schema changes go in a new `internal/db/migrations/NNNNN_name.sql` goose file. Never edit an applied migration.
- **API:** edit `api/openapi.yaml`, run `make generate`, then implement the new method on `*api.Server` in the resource's file under `internal/api/`.

## Tests

- Unit: `make test`. No external services.
- Integration: files start with `//go:build integration`. `dbtest.New(t)` returns a migrated pool on a fresh database inside one Postgres 16 container per test binary.
- E2E: files in `test/e2e/` start with `//go:build e2e` and hit `CF_E2E_BASE_URL` (default `http://localhost:8080`). `make e2e` also runs the issuance test (`test/e2e/issuance_test.go`), which drives the running compose server through its HTTP API — log in (or complete first-run setup), create a CA/credential/account/certificate against Pebble and challtestsrv, poll for `active`, verify the chain, force a renewal, then break the credential and verify the resulting failure and backoff. The `e2e-challtestsrv` DNS provider (`internal/challenge/challtestsrv_e2e.go`) exists only in `-tags e2e` builds; the test compose builds the server with `GO_TAGS=e2e` so the running server can present TXT records on pebble-challtestsrv. `test/e2e/oidc_test.go` enables single sign-on against the compose dex (issuer `http://dex:5556/dex`, user `oidc-user@example.test` / `password`), logs in through dex's password form, binds the new user as viewer and checks `/auth/me`, the `session.login` audit event and the audit chain, then exercises user disable, API key issue/bearer use/revoke, role binding list/delete, org/site CRUD and audit list/export. Right after the first local admin login it `PUT`s `loginRatePerMinute: 0` on the `authentication` settings section (0 disables the limit; `internal/authn/settings.go`) so repeated logins across this test and the Phase 2B Playwright suite, which reuses the same running stack, never hit 429.

| Build tag | Purpose |
|---|---|
| `integration` | Postgres-backed tests via testcontainers |
| `e2e` | Tests against the running compose stack |
| `embedweb` | Embed `internal/webui/dist` instead of the placeholder page |

## Commits and progress

- One commit per plan task, made only after `make lint test test-integration` passes.
- Author `metril <1517921+metril@users.noreply.github.com>`. Conventional prefix with scope, for example `feat(authn): ...`.
- Each commit updates `docs/PROGRESS.md` and `CHANGELOG.md`, plus the docs for the code it changes.

## Adding a settings section

Register it at startup in `cmd/certforge/serve.go`:

```go
sections.MustRegister("my_section", json.RawMessage(schemaJSON), json.RawMessage(`{}`))
```

The default must validate against the schema. Every property needs `title` and `description` because the UI builds the form and tooltips from them.

## Adding an API operation

1. Add the path, with `operationId`, `description`, and schemas that describe every field, to `api/openapi.yaml`.
2. `make generate`.
3. Implement the new `gen.StrictServerInterface` method on `*api.Server` in `internal/api/<resource>.go`. Return `*api.HTTPError` for 4xx responses. Check permissions with `authorize(ctx, authz.ActionX, orgID)`.
4. If the route must work without a session, add it to `isPublic` in `internal/api/router.go`.

Unknown paths under `/api/` and panics anywhere get an `application/problem+json` response; a missing file under `/api/docs/` is served by `http.FileServer` and keeps its plain `text/plain` 404.

## Registering a pluggable type schema

```go
metaReg.Add(meta.KindDNSProvider, meta.Entry{Code: "cloudflare", Name: "Cloudflare", Schema: schemaJSON})
```

It appears in `GET /api/v1/meta/schemas`, and the UI renders its form from the schema.

## Frontend

The web UI lives in `web/` (Vite, React 18, TypeScript strict, Tailwind 4, shadcn/ui on Radix).

| Command (in `web/`) | What it does |
|---|---|
| `npm install` | Install exact-pinned dependencies (Node 24) |
| `npm run dev` | Dev server on :5173; `/api`, `/readyz`, `/healthz` proxy to `CF_DEV_BACKEND` (default `http://localhost:${CF_HTTP_PORT:-8080}`) |
| `npm run gen` | Regenerate `src/api/schema.d.ts` from `api/openapi.yaml` and `src/routeTree.gen.ts` from `src/routes` |
| `npm run lint` / `typecheck` / `test` | ESLint, `tsc -b`, Vitest |
| `npm run build` | Production build to `web/dist`, embedded by the server with `-tags embedweb` |
| `npm run e2e` | Playwright smoke test against a running compose.test stack |

Rules enforced in code:
- Native checkboxes and radio buttons fail lint. Use `SwitchField`, `ChipSet`, or `SegmentedControl`.
- Colours come only from `src/styles/tokens.css`; `tokens.test.ts` checks both themes for WCAG AA.
- Tooltip copy lives in `src/lib/help.ts`; `help.test.ts` rejects entries over two sentences and "Learn more" links to missing doc headings.
- Theme is applied before first paint by `public/theme-init.js`, loaded synchronously in `<head>`.

### Docker

`deploy/Dockerfile.server` builds the UI in a `node:24-alpine` stage and copies `web/dist` into `internal/webui/dist` in the Go stage, which builds with `-tags embedweb`. `ARG WITH_WEB` defaults to `1`, so both a plain `docker build -f deploy/Dockerfile.server .` and `docker compose -f deploy/compose.yaml up --build` embed the UI:

```bash
docker build -f deploy/Dockerfile.server -t certforge:web .          # serves the UI (default)
docker build -f deploy/Dockerfile.server --build-arg WITH_WEB=0 -t certforge:api .   # placeholder page only
```

Locally, `npm run build` (in `web/`) then `make build-embed` does the same without Docker. `internal/webui`'s own tests (`TestSPAFallback`, `TestPlaceholder`) cover both binaries: the embedweb-tagged one falls back to `index.html` for client-side routes and caches `/assets/*` immutably; the plain build serves a small "CertForge" placeholder page instead.

`deploy/Dockerfile.agent` builds `certforge-agent` alone (no web stage) into the same distroless base, running as root so it can chown layout files; see [agent.md → Running with Docker](agent.md#running-with-docker). `make image-agent` builds it as `ghcr.io/metril/certforge-agent:dev`.

### Browser smoke test

A Playwright test drives the built UI against a real compose stack (Postgres, the certforge image, Pebble, and challtestsrv), exactly like a browser would — no mocked network:

```bash
docker compose -p certforge-e2e -f deploy/compose.yaml -f deploy/compose.test.yaml up -d --build --wait
cd web && npx playwright install chromium && npm run e2e
docker compose -p certforge-e2e -f deploy/compose.yaml -f deploy/compose.test.yaml down -v
```

(The Makefile's `COMPOSE_TEST` variable is the same two-file, `-p certforge-e2e` invocation. If the default port 8080 is already taken on the host, set `CF_HTTP_PORT` — for example `18080` — on all three commands; `web/e2e/env.ts`'s default base URL already reads it. `deploy/dex/config.yaml`'s `staticClients[].redirectURIs` only lists `http://localhost:8080/...` and `http://localhost:18080/...`: the OIDC e2e test only works at those two host ports out of the box, and a different `CF_HTTP_PORT` needs a matching redirect URI added to that file first.) `web/e2e/global-setup.ts` completes first-run setup if needed (or logs in, on a rerun against a stack that already has it), then creates a Pebble CA, an ACME account, a challtestsrv DNS credential, and a `smoke` certificate through the running server's own HTTP API — never in-process — and waits for it to go `active`. `web/e2e/smoke.spec.ts` then drives the UI itself, in both themes: sign in, the certificate list (validity bar, next-renewal chip), the detail page (including that the Coverage panel actually shows the matching rule, not "No matching rule" — a real-browser regression check, see CHANGELOG), the Attempts tab and raw log viewer, and a PEM download (asserting the downloaded filename ends `.pem` and its content starts with a `-----BEGIN CERTIFICATE-----` block); a further test resizes to 375px and drags a name chip onto "Common name" in the wizard's Names step to confirm chips wrap without horizontal page scroll and the drag reassigns the CN. Screenshots land at `web/test-results/screens/{light,dark}-{certificates,detail,attempts}.png`. Override targets with `CF_E2E_BASE_URL`, `CF_E2E_ADMIN_PASSWORD`, `CF_E2E_ORG`, `CF_E2E_ACME_DIR`, `CF_E2E_TRUST_BUNDLE`, `CF_E2E_RESOLVERS`, and `CF_E2E_DNS_PROVIDER` (see `web/e2e/env.ts`).

`web/e2e/oidc.spec.ts` enables single sign-on against the compose dex, signs in as `oidc-user@example.test` / `password`, binds that user as viewer through the API and checks the org appears (it turns single sign-on off again afterwards). `web/e2e/audit.spec.ts` opens the Audit log in both themes, checks the chain chip, an event diff under All orgs, and the CSV export, then checks that the Phase 2 screens do not scroll sideways at 375 px. Chromium maps the host name `dex` to `127.0.0.1` (`web/playwright.config.ts`'s `--host-resolver-rules`), so dex must be reachable at host port 5556 (leave `CF_DEX_PORT` unset). Tests run one at a time (`workers: 1` in `web/playwright.config.ts`) because every sign-in revokes that account's other sessions; `web/e2e/global-setup.ts` also `PUT`s `loginRatePerMinute: 0` on the `authentication` settings section right after its first admin login, idempotently, so repeated logins across this suite and the Go e2e (`test/e2e/oidc_test.go`, ruling C7) never hit the login rate limit.

This is a local/manual step, not part of `.github/workflows/ci.yml`: it needs a from-source Docker build plus a real ACME issuance against Pebble to reach `active`, several minutes even on a warm cache, and the repository's Go e2e test (`make e2e`) is likewise not run in CI today.

### Conventions

- Server state lives in TanStack Query; query keys start with the resource and org id (`['certs', orgId, …]`) so one invalidation refreshes lists, details, and the overview.
- API calls live only in `src/api/queries/*`; components never call `api` directly.
- Every tooltip string is a `help.ts` key. A "Learn more" link must point at a heading that exists in `docs/`.
