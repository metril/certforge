# Development

## Prerequisites

- Go 1.26 (go.mod sets 1.26.0; the go command downloads that toolchain itself when the installed one is older)
- Docker: integration tests use testcontainers, e2e uses compose
- A C compiler (gcc or clang): `make generate` builds sqlc, which needs cgo
- GNU make and curl

The `go` directive in `go.mod` pins the toolchain; leave `GOTOOLCHAIN` at its default (`auto`) so an older local Go fetches the required one.

## Repository layout

| Path | Contents |
|---|---|
| `api/openapi.yaml` | API source of truth. Go server stubs (and later the TS client) are generated from it |
| `cmd/certforge/` | Server binary: `serve`, `migrate`, `bootstrap-admin`, `backup`, `restore`, `healthcheck`, `version` |
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
| `internal/delivery/`, `internal/deploy/`, `internal/targets/` | Layouts and Traefik rendering; server-run deploy; the shared deploy-target model |
| `cmd/cfctl/` | The command-line client |
| `tools/gen-lego-schemas/` | Generates DNS provider schemas and `docs/reference/dns-providers.md` |
| `deploy/` | Dockerfiles and compose files (`compose.yaml` builds locally; `compose.release.yaml` pulls `ghcr.io/metril/certforge:$CF_VERSION`) |
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
| `make e2e-web` | Fresh compose stack with the agent service, then the whole Playwright suite; tears the stack down after |
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
| `CF_CHALLTESTSRV_PORT` | `18055` | pebble-challtestsrv management API (also sets `CF_E2E_CHALLTESTSRV`; the breadth e2e adds the A records Pebble's http-01/tls-alpn-01 validation resolves against here, and independently `docker inspect`s the certforge/traefik/agent containers' compose-network IPs to point them at) |
| `CF_VAULT_PORT` | `8200` | dev-mode Vault (also sets `CF_E2E_VAULT`, `http://localhost:$CF_VAULT_PORT`, for the Vault e2e's own direct reads of the KV document and Vault's PKI CA) |
| `CF_E2E_VAULT_TOKEN` | `certforge-e2e-root` | Vault's dev-mode root token (`VAULT_DEV_ROOT_TOKEN_ID`); also the value `deploy/e2e/vault-init.sh` sets as the e2e AppRole's fixed `secret_id` (`custom-secret-id`, deterministic rather than Vault-generated, so a rerun never needs to re-read it) |
| `CF_MAILPIT_PORT` | `18025` | mailpit's HTTP API (the ops e2e's "smtp" settings section always points at `mailpit:1025` over the compose network; the host-side test reads delivered messages back through this published port). `make e2e-web` exports it too, for `web/e2e/ops.spec.ts`'s own "SMTP test via mailpit" (same read-back, through `web/e2e/env.ts`'s `mailpitApi`) |
| `CF_E2E_SINK_PORT` | `18090` | Not a compose port: the host address the ops e2e's own webhook sink listens on (`0.0.0.0:$CF_E2E_SINK_PORT`), reached by the compose server as `http://host.docker.internal:$CF_E2E_SINK_PORT/hook` (`deploy/compose.test.yaml`'s `certforge.extra_hosts: host.docker.internal:host-gateway`). A host firewall that blocks inbound connections from the Docker bridge network (rather than just the loopback interface) needs a rule allowing it, the same as any other container-to-host traffic. `make e2e-web` exports it too, for `web/e2e/alerts.spec.ts`'s own "channel CRUD with webhook test" (`web/e2e/sink.ts`'s `startSink`, the Playwright-side mirror of `opsWebhookSink` below) |

The Go e2e tests (`test/e2e/`, build tag `e2e`) drive the running compose stack through its HTTP API, the way a real client would. They talk to Pebble and challtestsrv only through the server, except for Pebble's management port, which they use to check an issued chain independently. Example: `CF_HTTP_PORT=18080 make e2e`.

| Test | What it proves |
|---|---|
| `issuance_test.go` | Create a CA, credential, account and certificate against Pebble, reach `active`, verify the chain, force a renewal, then break the credential and check the failure and backoff. The `e2e-challtestsrv` DNS provider exists only in `-tags e2e` builds, and the test compose builds the server with `GO_TAGS=e2e`. |
| `oidc_test.go` | Single sign-on against the compose dex, user and API key lifecycle, role bindings, org and site CRUD, audit list and export. It sets `loginRatePerMinute: 0` right after the first admin login so repeated logins never hit the limit. |
| `issuance_breadth_test.go` | HTTP-01 served by the server and by the agent, TLS-ALPN-01 via the agent, a mixed DNS-01 and HTTP-01 certificate, a PKCS#12 export, and an ARI window, against a Traefik service. |
| `agent_test.go` | An enrolled agent through a TLS-terminating proxy (below): enrolment with approval, sessions, a deploy that matches the certificate's fingerprint, drift and automatic remediation, a server restart with the agent reconnecting, and grant deletion pruning the files. |
| `vault_test.go` | Vault Transit, private CAs, Vault PKI and Vault KV. It restarts the server onto Transit with the static key kept as previous, runs re-encryption, and checks the audit chain survives. Runs as its own invocation after the rest. |
| `ops_test.go` | Webhook and SMTP delivery of `cert.issued`, an external monitor against Traefik, `/metrics`, `cfctl`, and a backup restored into a fresh database with the audit chain intact. Also runs as its own invocation. |

### The agent goes through Caddy
The compose agent does not reach the server directly. `deploy/e2e/Caddyfile` runs Caddy (`caddy:2.8.4-alpine`, profile `e2e`) as a TLS-terminating proxy at `https://caddy:9443` with its internal CA, forwarding to the server's HTTP port only. The test sets the **Agent URL** to that address, so enrolment, approval, sessions, deploys and the WebSocket all cross a hop that sees plaintext HTTP. The agent trusts Caddy's root through `SSL_CERT_FILE`. The test reads Caddy's access log (`.e2e/caddy/access.log`) to confirm the agent's `hello`, `session` and `assignments` calls went through it.

The agent requires approval like any other, so `agent_test.go` polls `GET /orgs/{org}/enrollment-requests` and approves the request through the API. The agent runs as the host user (`CF_E2E_UID`, `CF_E2E_GID`, set by `make e2e`), so the test can tamper with and clean up its files. Its mounts (`.e2e/agent-data`, `.e2e/traefik`, `.e2e/ssl`, `.e2e/caddy`) live under the git-ignored `.e2e/` directory, which the `e2e` targets recreate on every run. Set `CF_AGENT_TRANSPORT` on the agent to pick its TLS roots; the Caddy setup uses the system roots path.

## Code generation

Generated code is committed. CI runs `make generate && git diff --exit-code`, so always regenerate and commit together.

- **SQL:** add a `-- name: X :one|:many|:exec|:execrows` query to a file in `internal/db/queries/`, then run `make generate`. Schema changes go in a new `internal/db/migrations/NNNNN_name.sql` goose file. Never edit an applied migration.
- **API:** edit `api/openapi.yaml`, run `make generate`, then implement the new method on `*api.Server` in the resource's file under `internal/api/`.

## Tests

- Unit: `make test`. No external services.
- Integration: files start with `//go:build integration`. `dbtest.New(t)` returns a migrated pool on a fresh database inside one Postgres 16 container per test binary. The agent protocol has integration tests that run the real agent against a terminating proxy and a hostile WebSocket proxy.
- E2E: see above.

| Build tag | Purpose |
|---|---|
| `integration` | Postgres-backed tests via testcontainers |
| `e2e` | Tests against the running compose stack |
| `embedweb` | Embed `internal/webui/dist` instead of the placeholder page |

## Commits and progress

- One commit per plan task, made only after `make lint test test-integration` passes.
- Author `metril <1517921+metril@users.noreply.github.com>`. Conventional prefix with scope, for example `feat(authn): ...`.
- Each commit updates `docs/internals/history/PROGRESS.md`, plus the docs for the code it changes. `CHANGELOG.md` is not hand-edited: release-please writes each release's section from the conventional commit messages on `main` (see Releases below).

## Releases

`.github/workflows/release.yml` runs on every push to `main`. [release-please](https://github.com/googleapis/release-please) reads the conventional commits since the last release, and either opens or updates a release PR (bumping the version, writing `CHANGELOG.md`) or, when that PR is merged, tags `vX.Y.Z`, creates the GitHub release, and the same workflow run then publishes both container images (`ghcr.io/metril/certforge`, `ghcr.io/metril/certforge-agent`, linux/amd64+arm64, provenance and SBOM attached, tagged `X.Y.Z`/`X.Y`/`latest`, plus `X` once the project is past `v0.`) and uploads `certforge-agent`/`cfctl` tarballs with a `SHA256SUMS` file to the release. Publishing lives in the same workflow as the tag because a tag created with the default `GITHUB_TOKEN` does not itself trigger other workflows.

A commit's footer can force a release version explicitly with a `Release-As: 1.2.3` trailer; release-please otherwise infers major/minor/patch from `feat`/`fix`/`!`-breaking commits (`bump-minor-pre-major: true`, so a `feat` bumps the minor version, not the major, while the project is at `0.x`).

One-time GitHub settings, needed before the first release PR merges:

- Recommended: add a fine-grained PAT (Contents + Pull requests read/write on `metril/certforge`) as the repo secret `RELEASE_PLEASE_TOKEN`. Without it, the release PR opens with `GITHUB_TOKEN` and gets no `ci.yml` run (GitHub does not run workflows off PRs opened by the default token) — enable Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests" instead if you skip the PAT.
- After the first image publish, set both GHCR packages (`certforge`, `certforge-agent`) to public.

The Go builder image (`golang:1.26-alpine` in both Dockerfiles) is a floating tag; pin image tags to digests before the first release PR is merged.

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

## Adding a notifier

A notifier delivers one `notify.Event` to one `notification_channels.type`
(`internal/notify/{webhook,discord,ntfy,homeassistant}.go` are the four HTTP
ones; `smtp.go` is the mail one). Implement `notify.Notifier`:

```go
type Notifier interface {
    Type() string
    Name() string
    Schema() []byte
    Send(ctx context.Context, ev Event, target Target, cfg map[string]any, secrets map[string]string) error
}
```

`Schema()` is an embedded JSON Schema (`//go:embed foo.schema.json`); mark a
field `"secret": true` to store it encrypted, split from `cfg` into `Send`'s
own `secrets` map. **Never give a secret property a `pattern`, `enum`,
`const` or `format` keyword** — a failed one echoes the rejected value into
the schema validator's error text, which would leak the secret into a
stored `last_error` or a 422 body (the same rule
`internal/settings.secretProps` enforces for settings sections). Validate a
secret field's shape in Go instead, through `notify.ConfigChecker`:

```go
func (MyNotifier) CheckConfig(cfg map[string]any) error { /* cfg is the full, pre-split input */ }
```

`(*notify.Registry).ValidateConfig(type, cfg)` runs the schema first, then
`CheckConfig` when the notifier implements it — channel
create and update call it before splitting secrets out.

An HTTP notifier builds its own `httpx.Client` in `Send` (never a shared
one, since `caPem` and the loopback policy are channel- and moment-specific)
and always calls `httpx.CheckURL` immediately before dialing, even though
the same URL was already checked at channel create/update — see
[Security model](../operations/security-model.md#notification-channel-secrets-and-url-policy). Register the
type in `cmd/certforge/serve.go` (`notifyReg.Register(...)`); it then
appears in `GET /api/v1/meta/schemas` via `notify.AddToMeta`.

A notifier that reads settings (any type that isn't purely per-channel
config, e.g. SMTP's saved section) takes a `SettingsFunc` field instead of
holding a value: `serve.go` wires it as a closure over the live
`*settings.Store` (`notifySettings := func(ctx context.Context) (notify.Settings, error) { return notify.Current(ctx, store) }`),
so every `Send` — including one running long after boot — re-reads the
current settings rather than a snapshot taken at registration. Every one of
the five built-in notifiers is registered this same way, right after
`notifyReg := notify.NewRegistry()`; `notify.Service` and `notify.Sources`
then share one `*notify.Registry` and one `*notify.Emitter` with it (see
[Architecture](architecture.md#event-fan-out-and-notifications)'s event fan-out diagram).

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

`deploy/Dockerfile.agent` builds `certforge-agent` alone (no web stage) into `gcr.io/distroless/static-debian12` — the same distroless family the server image uses, but its plain (root) tag, not the server's `:nonroot` one, since the agent runs as root by default so it can chown layout files; see [Agents → Running with Docker](../guide/agents.md#running-with-docker). `make image-agent` builds it as `ghcr.io/metril/certforge-agent:dev`.

### Browser smoke test

Playwright drives the built UI against a real compose stack (Postgres, the server, Pebble, challtestsrv, dex, Vault, mailpit and the agent behind Caddy), with no mocked network:

```bash
docker compose -p certforge-e2e -f deploy/compose.yaml -f deploy/compose.test.yaml up -d --build --wait
cd web && npx playwright install chromium && npm run e2e
docker compose -p certforge-e2e -f deploy/compose.yaml -f deploy/compose.test.yaml down -v
```

`make e2e-web` does this in one step and exports the ports the specs need. If port 8080 is taken, set `CF_HTTP_PORT` (for example `18080`) on every command. `deploy/dex/config.yaml` lists redirect URIs only for host ports 8080 and 18080, so the OIDC spec works at those two out of the box; another port needs a matching redirect URI first.

`web/e2e/global-setup.ts` completes first-run setup (or logs in on a rerun), turns the login rate limit off, then creates a Pebble CA, an ACME account, a challtestsrv DNS credential and a `smoke` certificate through the API and waits for it to become `active`. Specs run one at a time (`workers: 1`) because every sign-in revokes that account's other sessions.

| Spec | Covers |
|---|---|
| `smoke.spec.ts` | Certificate list, detail, attempts, PEM download, wizard drag at 375 px. |
| `oidc.spec.ts`, `audit.spec.ts` | Single sign-on; the audit log in both themes, chain chip, diff, CSV export. |
| `certificates.spec.ts` | PKCS#12 download, upload, import dry run, wizard verification step, issuance defaults. |
| `issuers.spec.ts`, `targets.spec.ts`, `vault.spec.ts` | Private CAs, server grants, deploy targets, Vault settings and the encryption key card. |
| `clients.spec.ts` | Sets the **Agent URL** to the Caddy address, creates a layout, enrols a client, waits for **Awaiting approval**, compares the verification code, approves, then checks Online, a grant, the Deployed state and the PEM under `.e2e/ssl/`. Needs a fresh stack: the agent enrols once. |
| `approval.spec.ts` | The waiting panel, the navigation badge, the approval dialog, and the **Require approval** setting. |
| `alerts.spec.ts`, `ops.spec.ts` | Channels, test events, monitors, SMTP via mailpit, `/metrics`, backup download. |
| `flow.spec.ts` | The Flow view. |

It is a local, manual step, not part of CI: it needs a from-source Docker build and real issuance against Pebble. Screenshots land in `web/test-results/screens`.

### Conventions

- Server state lives in TanStack Query; query keys start with the resource and org id (`['certs', orgId, …]`) so one invalidation refreshes lists, details, and the overview.
- API calls live only in `src/api/queries/*`; components never call `api` directly.
- Every tooltip string is a `help.ts` key. A "Learn more" link must point at a heading that exists in `docs/`.
