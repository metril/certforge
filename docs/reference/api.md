# API reference

The REST API lives under `/api/v1`. The complete list of operations, parameters and schemas is the OpenAPI document: the source file is `api/openapi.yaml`, the running server serves it as JSON at `/api/v1/openapi.json` (no sign-in needed) and as an interactive page at `/api/docs/`. This page covers what the document does not: authentication, permissions, conventions, and the routes outside it. For a command-line client, see [cfctl](cfctl.md).

## Authentication

| Caller | How it authenticates |
|---|---|
| Browser | `POST /auth/login` (local admin) or `GET /auth/oidc/start` (single sign-on) sets the `cf_session` cookie. Writes with a session must send the session's `X-CSRF-Token`, returned by `GET /auth/me`. |
| Script | An API key: `Authorization: Bearer cf_<prefix>_<secret>`. No CSRF header is needed. |
| certforge-agent | Not this API. See [Agent routes](#agent-routes). |

`GET /auth/methods` is public and tells a client whether single sign-on and the local admin are available. The other public routes are `GET /setup/status`, `POST /setup/complete`, `GET /auth/oidc/callback` and `GET /openapi.json`.

If a request carries both a valid bearer token and a cookie, the bearer token decides. A bearer value that is not a CertForge key (for example an upstream proxy's header) is ignored.

### API keys

Create keys under **Settings → Access → API keys** (see [Access](../guide/access.md)). The token is shown once; only its SHA-256 is stored. A key can do at most what its creator can do right now, narrowed to its scopes and to its organization when it has one. Keys cannot create keys. A key stops working when it is revoked, expires, or its creator is disabled. Limits on lifetime and count are in [Configuration](configuration.md#authentication).

| Scope | Allows |
|---|---|
| `certs:read` | Read certificates, and also organizations, sites, CAs, ACME accounts and DNS credentials. |
| `certs:write` | Create, edit and delete certificates. |
| `certs:issue` | Renew now, confirm manual DNS. |
| `keys:export` | Download private keys; create grants that deliver a key. |
| `dnscreds:reveal` | Read DNS credentials and reveal one stored secret field. |
| `clients:read` / `clients:write` | Read, or read and change, clients and grants (read also covers organizations and sites). |
| `delivery:read` / `delivery:write` | Read, or read and change, layouts, deploy targets and hooks. |
| `alerts:read` / `alerts:write` | Read, or read and change, channels, monitors and events. |
| `admin` | Everything the creator can do. |

## Permissions and roles

Each operation checks one permission in the organization named by `{orgId}`, or globally. A role binding grants a role to a user, an OIDC group or an API key, in one organization or globally.

| Role | Allows |
|---|---|
| `admin` (global) | Everything. |
| `org-admin` | Everything in its organization except the global-only permissions: `settings:write`, `orgs:write`, `cas:write`, `keys:export`, `users:write`, `dnscreds:reveal`. |
| `operator` | Everything a viewer can read, plus write access to ACME accounts, DNS credentials, certificates (including renew), clients, delivery and alerts. |
| `viewer` | Read access to organizations, settings, CAs, ACME accounts, DNS credentials, certificates, clients, sites, delivery and alerts. |
| `auditor` | Viewer, plus `audit:read`. |

Reading the audit log with global `audit:read` shows every event. An organization-scoped `audit:read` shows only that organization's events. `GET /audit/verify` needs global `audit:read`.

## Conventions

**Errors** are `application/problem+json` (RFC 9457) with `title` and `detail`. Codes: 400 bad request, 401 unauthenticated, 403 missing permission or CSRF failure, 404 not found (also for things you cannot see), 409 conflict or in use, 413 body over 1 MiB, 415 body not JSON, 422 invalid input (the title names the field), 429 rate limited (with `Retry-After`), 502 the CA or identity provider rejected the request, 503 busy (with `Retry-After`).

**Request bodies** are JSON, at most 1 MiB. Endpoints that take a file (certificate upload and import) document their own type and limit in the OpenAPI document.

**Lists** that can grow (certificates, clients, events, audit) are keyset-paginated. They take `limit` (1–500, default 50) and `cursor` and return `{items, nextCursor}`; pass `nextCursor` back unchanged, and it is null on the last page. A cursor only continues the request that produced it. Small collections (CAs, accounts, DNS credentials, versions, attempts) return plain arrays.

**Write-only secrets** are never returned: ACME `eabHmac`, DNS credential fields marked secret, deploy target and channel secrets, and settings marked secret. Responses list which hold a value (`storedSecrets`). On update, `__unchanged__` or omitting the field keeps the stored value and `""` clears it. A DNS credential's secret field can be revealed once by a global admin (`POST .../dns-credentials/{id}/reveal`), and every reveal is audited.

**Settings** are read and written with `GET` and `PUT /settings/{section}`. The sections and their fields are in [Configuration](configuration.md#settings).

**Audit export**: `GET /audit/export` streams the filtered log as CSV, at most 100 000 rows. `X-Audit-Truncated: true` means the cap was hit; a failure part-way writes a final `#error` row instead of a silently short file.

## Enrolment requests

When [Require approval](configuration.md#agents) is on, an agent that presents a valid token waits as a pending request until an administrator decides. See [Clients](../guide/clients.md#approval).

| Operation | Permission | Meaning |
|---|---|---|
| `GET /enrollment-requests` | `clients:read` | Waiting requests across every organization you can read. Items carry `orgId`. |
| `GET /orgs/{orgId}/enrollment-requests` | `clients:read` | Waiting requests in one organization, oldest first, not paginated. At most 50 wait per organization. Expired requests are not listed. |
| `POST /orgs/{orgId}/enrollment-requests/{id}/approve` | `clients:write` | The agent receives its certificate at its next poll and the client becomes active. 204. |
| `POST /orgs/{orgId}/enrollment-requests/{id}/reject` | `clients:write` | The agent is told it was rejected and stops. The token stays used, so re-enrol the client for a new one. 204. |

Approve and reject return 409 when the request was already decided or has expired, and 404 when it does not exist in this organization. They are audited as `client.enrol_approved` and `client.enrol_rejected`.

## Routes outside the API

These are not under `/api/v1` and not in the OpenAPI document.

| Route | Auth | Meaning |
|---|---|---|
| `GET /healthz` | none | Liveness. |
| `GET /readyz` | none | Readiness: database, encryption key, and Vault when in use. See [Monitoring](../operations/monitoring.md). |
| `GET /metrics` | bearer token | Prometheus scrape target. 404 while disabled in **Settings → Integrations → Prometheus**; 401 with `WWW-Authenticate: Bearer` for a missing or wrong token. |
| `GET /.well-known/acme-challenge/{token}` | none | Serves the http-01 key authorization for a token this server is currently waiting on, as `text/plain`; 404 otherwise. See [Challenges](../guide/challenges.md#http-01). |
| `GET /crl/{caId}.crl` | none | A private CA's current CRL, DER, `Cache-Control: max-age=600`. |
| `GET /crl/{caId}/{issuerSerial}.crl` | none | The CRL of any issuer the CA has held (lower-case hex serial). 404 for an unknown CA or issuer, a CA that is not a private CA, or `crl: false`. See [Issuers](../guide/issuers.md#crl). |
| `/agent/v1/*` | signed and sealed | The agent protocol. |

### Agent routes

certforge-agent does not call `/api/v1`. It uses `/agent/v1/*`, served on the agent listener (`CF_LISTEN_AGENT`) and also on the HTTP listener, so agents work behind a TLS-terminating proxy. Agents do not authenticate with TLS client certificates. Each request is signed with the agent's key and travels inside a sealed session; enrolment proves possession of the one-time token. The routes are `GET /enroll/hello`, `POST /enroll`, `POST /enroll/{id}`, `POST /session`, `GET /ws`, then `POST /renew`, `GET /assignments`, `GET /grants/{id}/bundle`, `POST /report` and `POST /heartbeat`. The protocol is specified in [Architecture](../internals/architecture.md#agent-protocol) and the limits in [agent.md](agent.md).

## See also

- `api/openapi.yaml` and `/api/docs/`
- [cfctl](cfctl.md)
- [Events](events.md)
- [Security model](../operations/security-model.md)
