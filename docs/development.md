# Development

## Prerequisites

- Go 1.23
- Docker: integration tests use testcontainers, e2e uses compose
- A C compiler (gcc or clang): `make generate` builds sqlc, which needs cgo
- GNU make and curl

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
| `deploy/` | Dockerfile and compose files |
| `test/e2e/` | Compose-driven end-to-end tests |

## Make targets

| Target | What it does |
|---|---|
| `make generate` | Runs sqlc and oapi-codegen at pinned versions |
| `make build` | Builds `bin/certforge` with the placeholder web page |
| `make build-embed` | Copies `web/dist` into `internal/webui/dist` and builds with `-tags embedweb` |
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
| `CF_CHALLTESTSRV_PORT` | `8055` | challtestsrv management API |

Pebble's ACME/management ports are not published to the host; certforge and
the e2e tests reach it over the compose network at `pebble:14000`. Example:
`CF_HTTP_PORT=18080 make e2e`.

## Code generation

Generated code is committed. CI runs `make generate && git diff --exit-code`, so always regenerate and commit together.

- **SQL:** add a `-- name: X :one|:many|:exec|:execrows` query to a file in `internal/db/queries/`, then run `make generate`. Schema changes go in a new `internal/db/migrations/NNNNN_name.sql` goose file. Never edit an applied migration.
- **API:** edit `api/openapi.yaml`, run `make generate`, then implement the new method on `*api.Server` in the resource's file under `internal/api/`.

## Tests

- Unit: `make test`. No external services.
- Integration: files start with `//go:build integration`. `dbtest.New(t)` returns a migrated pool on a fresh database inside one Postgres 16 container per test binary.
- E2E: files in `test/e2e/` start with `//go:build e2e` and hit `CF_E2E_BASE_URL` (default `http://localhost:8080`).

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
