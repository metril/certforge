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

The issuance e2e test drives the compose server through its own HTTP API
(`CF_E2E_BASE_URL`), the same way a real client would; it never talks to
Pebble or challtestsrv directly — only the compose server does, over the
compose network (`pebble:14000`, `challtestsrv:8055`/`:8053`). Pebble's
management port is the one exception, published to the host so the test can
independently check the chain it got back through the API against Pebble's
own roots/intermediates. Example: `CF_HTTP_PORT=18080 make e2e`.

`test/e2e/issuance_breadth_test.go`'s `TestIssuanceBreadthAgainstCompose`
(Phase 4A Task 15) proves the issuance breadth added across 4A end to end,
against the same stack plus a `traefik` service (profile `e2e`, file
provider only, no TLS serving): a certificate verified by the server's own
http-01, one verified by the compose agent's http-01 listener and reached
only through the per-grant Traefik ACME router file the agent writes
(`certforge-acme-<name>.yml`), one verified by the agent's tls-alpn-01
listener, a certificate mixing dns-01 and http-01 rules, a PKCS#12 export
decoded with `go-pkcs12`, and a populated ACME Renewal Information window.
It reaches pebble-challtestsrv directly (`CF_E2E_CHALLTESTSRV`) to add the
A records Pebble's validation needs, and shares one enrolled agent
(`enrolledAgent`, `test/e2e/agent_test.go`) with `TestAgentAgainstCompose`.

`test/e2e/vault_test.go`'s `TestVaultAgainstCompose` (Phase 5A Task 14)
proves Vault Transit, private CAs, Vault PKI and Vault KV end to end. The
stack first boots certforge on the static KEK like every other e2e test;
this test alone then restarts it (`docker compose ... -f
deploy/compose.vault.yaml up -d --no-deps --force-recreate certforge`) with
Transit active and the static key kept as previous, so `verifyAuditChain`
proves the audit chain survives that boundary and the rewrap has real
sealed rows to move (`POST /keys/rewrap`, polled via `GET /keys/status`
until `rewrap.finishedAt` is set and `remaining == 0`). It then creates a
`localca` CA and certificate, verifies the downloaded chain against the
CA's own `trustBundlePem`, fetches `GET /crl/{caId}.crl`, revokes the
version and confirms the refetched CRL lists its serial; configures
Settings → Integrations → Vault and `testVaultSettings`, creates a
`vaultpki` CA and certificate, and checks its trust bundle equals Vault's
own `pki/cert/ca`; creates a `vault-kv` deploy target and a server grant on
the `localca` certificate, waits for `serverDeployment.status ==
"deployed"`, and reads the KV document directly with Vault's root token
(`CF_E2E_VAULT`) to confirm `fullchain.pem` matches and `privkey.pem` is
absent (`includeKey` was never set); and finally `docker compose ... pause
vault` (dev-mode Vault is in-memory, so it is paused rather than stopped)
to check `/readyz` reports `checks.vault: failed` within 60s, then unpauses
and checks it recovers. `deploy/e2e/vault-init.sh` (run once by the
`vault-init` service, profile `e2e`, right after `vault` itself becomes
healthy) enables transit and pki, verifies dev-mode's default `secret/`
kv-v2 mount, and writes a fixed AppRole `role_id`/`secret_id` to
`../.e2e/vault` for this test's own second boot to read. `make e2e` runs
this test as its own `go test -run TestVaultAgainstCompose` invocation
after the rest of the suite passes (`-skip TestVaultAgainstCompose` on the
first), since it is the only test that restarts and reconfigures the
server out from under the rest of the stack. OpenBao is untested even with
this e2e in place — see [vault.md#openbao](vault.md#openbao) — it runs a
real HashiCorp Vault image, never OpenBao.

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
`CheckConfig` when the notifier implements it — Task 6's channel
create/update calls it before splitting secrets out.

An HTTP notifier builds its own `httpx.Client` in `Send` (never a shared
one, since `caPem` and the loopback policy are channel- and moment-specific)
and always calls `httpx.CheckURL` immediately before dialing, even though
the same URL was already checked at channel create/update — see
[`notifications.md#url-policy`](notifications.md#url-policy). Register the
type in `cmd/certforge/serve.go` (`notifyReg.Register(...)`); it then
appears in `GET /api/v1/meta/schemas` via `notify.AddToMeta`.

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

`deploy/Dockerfile.agent` builds `certforge-agent` alone (no web stage) into `gcr.io/distroless/static-debian12` — the same distroless family the server image uses, but its plain (root) tag, not the server's `:nonroot` one, since the agent runs as root by default so it can chown layout files; see [agent.md → Running with Docker](agent.md#running-with-docker). `make image-agent` builds it as `ghcr.io/metril/certforge-agent:dev`.

### Browser smoke test

A Playwright test drives the built UI against a real compose stack (Postgres, the certforge image, Pebble, and challtestsrv), exactly like a browser would — no mocked network:

```bash
docker compose -p certforge-e2e -f deploy/compose.yaml -f deploy/compose.test.yaml up -d --build --wait
cd web && npx playwright install chromium && npm run e2e
docker compose -p certforge-e2e -f deploy/compose.yaml -f deploy/compose.test.yaml down -v
```

(The Makefile's `COMPOSE_TEST` variable is the same two-file, `-p certforge-e2e` invocation. If the default port 8080 is already taken on the host, set `CF_HTTP_PORT` — for example `18080` — on all three commands; `web/e2e/env.ts`'s default base URL already reads it. `deploy/dex/config.yaml`'s `staticClients[].redirectURIs` only lists `http://localhost:8080/...` and `http://localhost:18080/...`: the OIDC e2e test only works at those two host ports out of the box, and a different `CF_HTTP_PORT` needs a matching redirect URI added to that file first.) `web/e2e/global-setup.ts` completes first-run setup if needed (or logs in, on a rerun against a stack that already has it), then creates a Pebble CA, an ACME account, a challtestsrv DNS credential, and a `smoke` certificate through the running server's own HTTP API — never in-process — and waits for it to go `active`. `web/e2e/smoke.spec.ts` then drives the UI itself, in both themes: sign in, the certificate list (validity bar, next-renewal chip), the detail page (including that the Coverage panel actually shows the matching rule, not "No matching rule" — a real-browser regression check, see CHANGELOG), the Attempts tab and raw log viewer, and a PEM download (asserting the downloaded filename ends `.pem` and its content starts with a `-----BEGIN CERTIFICATE-----` block); a further test resizes to 375px and drags a name chip onto "Common name" in the wizard's Names step to confirm chips wrap without horizontal page scroll and the drag reassigns the CN. Screenshots land at `web/test-results/screens/{light,dark}-{certificates,detail,attempts}.png`. Override targets with `CF_E2E_BASE_URL`, `CF_E2E_ADMIN_PASSWORD`, `CF_E2E_ORG`, `CF_E2E_ACME_DIR`, `CF_E2E_TRUST_BUNDLE`, `CF_E2E_RESOLVERS`, and `CF_E2E_DNS_PROVIDER` (see `web/e2e/env.ts`).

`web/e2e/oidc.spec.ts` enables single sign-on against the compose dex, signs in as `oidc-user@example.test` / `password`, binds that user as viewer through the API and checks the org appears (it turns single sign-on off again afterwards). `web/e2e/audit.spec.ts` opens the Audit log in both themes, checks the chain chip, an event diff under All orgs, and the CSV export, then checks that the Phase 2 screens do not scroll sideways at 375 px. Chromium maps the host name `dex` to `127.0.0.1` (`web/playwright.config.ts`'s `--host-resolver-rules`), so dex must be reachable at host port 5556 (leave `CF_DEX_PORT` unset). Tests run one at a time (`workers: 1` in `web/playwright.config.ts`) because every sign-in revokes that account's other sessions; `web/e2e/global-setup.ts` also `PUT`s `loginRatePerMinute: 0` on the `authentication` settings section right after its first admin login, idempotently, so repeated logins across this suite and the Go e2e (`test/e2e/oidc_test.go`, ruling C7) never hit the login rate limit.

`web/e2e/clients.spec.ts` sets the agents URL to `https://certforge:8443`, creates a layout, enrols a client and writes its token to `.e2e/agent-data/token` (the compose agent's `CF_AGENT_TOKEN_FILE`), waits for Online, grants the `smoke` certificate, checks Deployed on the client and the certificate's Deployments tab and the PEM under `.e2e/ssl/`, screenshots each screen in both themes, and checks the new screens at 375 px. Run it with `CF_HTTP_PORT=18080 make e2e-web`; it needs a fresh stack because the agent enrols only once.

`web/e2e/certificates.spec.ts` covers 4B's export, upload and import screens against the compose stack: downloading the `smoke` certificate as PKCS#12 (asserting the suggested filename and a non-empty file), uploading a keyless PEM certificate through `/certificates/upload` (asserting the **Managed externally** chip and a disabled Renew now), an import dry run against a fixture acme.sh archive (asserting a **Create** row, without ever clicking Import for real), the wizard's Verification step with a rule set to HTTP, the New layout sheet with a PKCS#12 file, and Settings → Issuance defaults' Global **Checks and limits** section, plus 375 px checks on the upload and import pages, the certificate detail page, and the detail page with the Download sheet open on PKCS#12. Its two fixtures come from `internal/importer/testdata/acmesh` (4A Task 14's self-signed material): `web/e2e/fixtures/upload.pem` is a copy of `ecc.acmesh.example.test_ecc/fullchain.cer` (the first entry in acme.sh's own directory order), and `web/e2e/fixtures/acmesh.zip` is built with `cd internal/importer/testdata/acmesh && python3 -m zipfile -c ../../../../web/e2e/fixtures/acmesh.zip *`, which puts the domain directories at the archive root. `web/e2e/screens.ts` holds the `setTheme`/`snap` helpers both this spec and `clients.spec.ts` import.

`web/e2e/issuers.spec.ts` covers 5B's private-CA and server-grant screens. "CA kind switching" opens New CA, walks ACME → Built-in CA → Vault PKI → Built-in CA checking each kind body's own first field (**Preset**, **Common name**, **Mount**), creates a `localca` CA named `e2e-local`, checks its Type chip and the type filter, then opens its detail sheet and checks the expiry text, downloads the trust bundle (asserting the filename ends `-ca.pem`), copies the CRL URL (read back from the real clipboard, permissions granted on the browser context), rotates with the confirm dialog, and checks exactly one retired-issuer chip appears. "server grant" sets up its own `vault` settings and a `localca` certificate through the admin API first — before the page signs in, since a local-admin login revokes that account's other sessions (`auth.ts`) — then creates a `vault-kv` deploy target through the UI, opens its Grants detail sheet, grants the pre-issued certificate, waits for a status chip (Pending, Deployed or Failed, bounded 60 s), and checks Redeploy toasts. A third test resizes to 375 px and checks the Issuers list and detail sheet, the Delivery targets list and its server target's detail sheet, and Settings → Integrations/Backup and keys, for horizontal scroll (workers: 1, file order — the same convention as `clients.spec.ts`'s own 375 px test — so the CA and target the first two tests create already exist).

`web/e2e/vault.spec.ts` covers Settings → Integrations and the encryption key card. "Vault settings test button" fills a bad address and token and checks the **Failed** chip, then the real `CF_E2E_VAULT_ADDR`/`CF_E2E_VAULT_TOKEN` and checks **Connected** (Vault is always up in the compose `e2e` profile, so this is unconditional), saves, reloads, and checks the token field shows the stored sentinel (a **Replace** button, not the raw value). "keys card" checks Settings → Backup and keys shows the KEK kind, a key id and **Canary OK**, and that **Rewrap now** is disabled with the `keys.rewrapNoPrevious` tooltip — e2e-web boots with a static KEK and no previous key (5A facts), so there's nothing to rewrap. Both specs run under `CF_HTTP_PORT=18080 make e2e-web`, which always starts the compose `vault` service in the `e2e` profile and exports `CF_E2E_VAULT_ADDR` (default `http://vault:8200`) and `CF_E2E_VAULT_TOKEN` for `web/e2e/env.ts` to read.

This is a local/manual step, not part of `.github/workflows/ci.yml`: it needs a from-source Docker build plus a real ACME issuance against Pebble to reach `active`, several minutes even on a warm cache, and the repository's Go e2e test (`make e2e`) is likewise not run in CI today.

`make e2e`'s compose stack adds an `agent` service, built from `deploy/Dockerfile.agent`, alongside the server, Pebble, challtestsrv and dex. It runs as the host user (`user: "${CF_E2E_UID}:${CF_E2E_GID}"`, set by the `e2e` target from `id -u`/`id -g`), not root, so `test/e2e/agent_test.go` can tamper with and clean up the files it writes; `CF_WRITE_ALLOW` covers both the layout mount (`/etc/ssl/certforge`) and the Traefik target mount (`/etc/traefik/dynamic`). All three of the agent's bind mounts (`.e2e/agent-data`, `.e2e/traefik`, `.e2e/ssl`) live under the gitignored `.e2e/` directory, which the `e2e` target removes and recreates on every run. `TestAgentAgainstCompose` sets the Agent URL to `https://certforge:8443` (the server's own compose network name — agents reach it directly, mTLS end to end, never through a proxy), creates a client, and writes its enrolment token to `.e2e/agent-data/token` for `CF_AGENT_TOKEN_FILE` to pick up: the container's `run` command polls for that file every 5s until it appears, so no separate `enroll` step is needed. It then proves a grant deploys a layout file and Traefik YAML matching the issued certificate's fingerprint, that tampering with the file drifts and (with `autoRemediate: true`) is restored automatically, that restarting the server (`CF_E2E_COMPOSE restart certforge`, the same two-file compose invocation as an absolute path so it works from the test's own working directory) leaves the agent reconnected and able to redeploy, and that deleting the grant removes both the YAML and the certificate files, pruning the Traefik target's per-certificate directory.

### Conventions

- Server state lives in TanStack Query; query keys start with the resource and org id (`['certs', orgId, …]`) so one invalidation refreshes lists, details, and the overview.
- API calls live only in `src/api/queries/*`; components never call `api` directly.
- Every tooltip string is a `help.ts` key. A "Learn more" link must point at a heading that exists in `docs/`.
