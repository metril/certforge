# API

Base path `/api/v1`. The OpenAPI document is `api/openapi.yaml`, served at `/api/docs`.

## Authentication and permissions

Browser sign-in: GET /auth/oidc/start (single sign-on) or POST /auth/login (local admin); both set the cf_session cookie. Session writes send X-CSRF-Token. API keys: see below. `GET /auth/methods` (public) tells a client whether single sign-on and the local admin are available. Each operation checks one permission for `{orgId}`:

| Permission | Operations | Roles |
|---|---|---|
| `cas:read` / `cas:write` | CA presets and CAs / add, edit, delete CAs | all / global admin |
| `accounts:read` / `accounts:write` | ACME accounts | all / admin, org-admin, operator |
| `dnscreds:read` / `dnscreds:write` | DNS credentials (never with secrets, except via `dnscreds:reveal`), test | all / admin, org-admin, operator |
| `certs:read` | defaults, certificates, versions, attempts, manual-dns records, PEM without key | all |
| `certs:write` | org defaults, create, edit, delete certificates | admin, org-admin, operator |
| `certs:issue` | renew now, confirm manual-dns | admin, org-admin, operator |
| `keys:export` | download `key` or `combined` (audited) | global admin |
| `dnscreds:reveal` | reveal one stored DNS credential secret field (audited) | global admin |
| `clients:read` / `clients:write` | clients, grants, deployments, hook runs | all / admin, org-admin, operator |
| `delivery:read` / `delivery:write` | layouts, deploy targets, hooks | viewer and up / admin, org-admin, operator |
| `alerts:read` / `alerts:write` | notification channels, monitors, events | viewer and up / admin, org-admin, operator |

certforge-agent does not call this API. It talks to `/agent/v1/*` on the agent listener (CF_LISTEN_AGENT) with its client certificate; see architecture.md → Agent protocol.

### API keys

Send `Authorization: Bearer cf_<prefix>_<secret>`. Keys need no CSRF header. A key can do at most what its creator can do right now, restricted to its scopes (`certs:read` also covers orgs, sites, CAs, accounts, DNS credentials; `clients:read` also covers orgs and sites; `clients:write` covers clients read and write; `delivery:read`/`delivery:write` cover layouts, deploy targets and hooks; `admin` is everything) and to its org when it has one. Keys stop working when revoked, expired, or when the creator is disabled. The token is returned once by `POST /api-keys`; only its SHA-256 is stored.

## Errors

Errors are `application/problem+json` (RFC 9457) with `title` and `detail`. 401 unauthenticated, 403 missing permission, 404 not found in this org, 409 in use or nothing to confirm, 422 invalid input (the title names the field), 502 the CA rejected the request (detail carries the ACME problem type).

Every operation in the served spec lists the problem responses it can return (components.responses). 429 comes with Retry-After.

## Lists

`GET /orgs/{orgId}/certificates` takes `status`, `q` (case-insensitive substring of the name or any certificate name), `sort` (`name`, `notAfter`, `nextRenewAt`, `status`; `-` prefix for descending), `limit` (1–500, default 50) and `cursor`, and returns `{items, nextCursor}`; pass `nextCursor` back unchanged, it is null on the last page. `GET /certificates` takes the same parameters across every org where you have `certs:read`; items carry `orgId`. The small collections (CAs, accounts, DNS credentials, versions, attempts, manual-dns records) return plain arrays.

`GET /audit` filters by `from`, `to` (exclusive), `actor`, `action` (exact, or a prefix ending in `.`), `resourceType`, `resourceId`, `orgId`, `q` (case-insensitive substring of action, resource, actor, IP or details); newest first; `limit` and `cursor` as elsewhere. Its `cursor` is unsigned (just base64 of a decimal id): authorization is re-derived from the caller on every request, and there is no sort/filter to bind it to since the chain has one order (id). `GET /audit/export` streams the same filters as `Content-Type: text/csv; charset=utf-8` (no BOM), columns `id,ts,actor_type,actor_id,actor_name,action,resource_type,resource_id,org_id,ip,details`, at most 100 000 rows; a cell a spreadsheet would read as a formula gets a leading apostrophe. The `X-Audit-Truncated` response header is `true` when the cap was hit. A query error partway through does not truncate the file silently: a final row `#error,export interrupted; see server log` is written instead (the detail is only in the server log, never the file) — every real data row's first column is a numeric id, so this row can't be mistaken for one. Exporting is itself recorded as `audit.export`. `GET /audit/verify` walks the whole hash chain and reports `{ok, count, brokenAtId, checkedAt, headHash}`, cached 60 seconds (`Deps.AuditVerifyTTL`); it needs global `audit:read` (the chain covers every org and global events, so an org-scoped auditor gets 403 even for their own org). `GET /audit` without global `audit:read` shows only the events of orgs where you have `audit:read`; global events (no org) need global `audit:read`. `GET /audit/{id}` fetches one event by its numeric id: it needs `audit:read` for the event's own org, or global `audit:read` for a null-org (global) event, and answers 404 — never 403, with the same message — whether the id doesn't exist or the caller just can't see it, so a probe can't tell the two apart.

## Write-only secrets

Secret fields (`eabHmac`, DNS credential fields marked `secret: true`) are never returned, with one exception: `POST .../dns-credentials/{id}/reveal` returns a single stored DNS credential secret field to a caller holding `dnscreds:reveal` (see below). On update, `__unchanged__` keeps the stored value. Settings sections follow the same rule; GET /settings/{section} returns storedSecrets. A field whose schema property is `serverPath: true` (usually a name ending `_FILE` or `_PATH`, plus a handful of fields overridden individually where the name doesn't follow that convention, such as infoblox's `INFOBLOX_CA_CERTIFICATE`) is rejected outright with 422: it names a path on lego's own host filesystem, which the API has no way to accept from a caller. Most such providers also have an inline field for the same material (used instead); a provider whose only field is a server path has no inline alternative and is marked `unsupported: true` in its schema — create/update return 422 for it until file-backed credentials arrive in Phase 5 (currently `transip` and `hyperone`). `GET /meta/schemas` still lists an unsupported provider (for the UI to grey it out), it just can't be configured yet.

DNS provider schemas may carry `x-auth-methods` (the alternative credential sets; create/update return 422 unless one is complete) and `x-alias-of` (marks an alias property, which the server folds into its canonical key; both set to different values is a 422).

`POST .../dns-credentials/{id}/test` never echoes a config value: a provider error is redacted before it reaches the response, the audit log, or (when the credential is later used for real issuance) an attempt's `lastError` — matched raw, URL-query-escaped, URL-path-escaped, and JSON-string-escaped, longest value first so a short value can't land inside and fragment a longer one. The call is bounded and gated: past a fixed timeout it answers `{ok:false, error:"timed out"}` while cleanup keeps running in the background (still counted against the concurrency limit until it finishes), and at most 2 tests run at once server-wide — beyond that it returns 503 with `Retry-After`.

## Endpoints

| Method and path | Purpose |
|---|---|
| `GET /meta/ca-presets` | CA presets with directory URL and `requiresEab` |
| `GET, POST /orgs` | list visible orgs, create (`orgs:write`, global admin) |
| `PATCH, DELETE /orgs/{orgId}` | rename (slug immutable), delete (409 while dependents exist) |
| `GET, POST /orgs/{orgId}/sites` | list, create sites |
| `PATCH, DELETE /orgs/{orgId}/sites/{id}` | rename, delete a site |
| `GET, POST /orgs/{orgId}/cas` | list, add CAs |
| `GET, PUT, DELETE /orgs/{orgId}/cas/{id}` | read, replace, delete a CA |
| `POST /orgs/{orgId}/cas/{id}/rotate` | rotate a `localca` CA's issuing key (422 for any other kind, or a `localca` CA with no held root key) |
| `GET, POST /orgs/{orgId}/acme-accounts` | list, register accounts |
| `GET, DELETE /orgs/{orgId}/acme-accounts/{id}` | read, delete an account |
| `GET, PUT /orgs/{orgId}/issuance-defaults` | org defaults (null inherits global) |
| `GET /orgs/{orgId}/issuance-defaults/effective` | resolved defaults with sources |
| `GET, PUT /settings/issuance_defaults` | global defaults (settings section) |
| `GET, PUT /settings/vault` | global Vault connection settings (settings section) |
| `POST /settings/vault/test` | test Vault connectivity with the given settings |
| `GET /keys/status` | key-encryption key status |
| `POST /keys/rewrap` | start rewrapping secrets under the active KEK |
| `GET, POST /orgs/{orgId}/dns-credentials` | list, add DNS credentials |
| `GET, PUT, DELETE /orgs/{orgId}/dns-credentials/{id}` | read, replace, delete a credential |
| `POST /orgs/{orgId}/dns-credentials/{id}/test` | create and remove a test TXT record |
| `POST /orgs/{orgId}/dns-credentials/{id}/reveal` | body `{field}`; returns `{field, value}` for one stored secret field. Needs `dnscreds:reveal` (global admin; API-key scope `dnscreds:reveal` or `admin`). Audited as `dns_credential.secret_revealed` before the value is returned (an audit failure gives 500 and no value); `Cache-Control: no-store`. 404 when the credential is missing or the field holds no value; 422 when the field is not a secret field |
| `GET, POST /orgs/{orgId}/certificates` | list, create (issues immediately) |
| `POST /orgs/{orgId}/certificates/upload` | store an existing certificate (PEM or PKCS#12) as unmanaged |
| `POST /orgs/{orgId}/certificates/import` | import an acme.sh or certbot archive (`multipart/form-data`; `dryRun` defaults true) as managed certificates; see [certificates.md#import](certificates.md#import) |
| `GET, PUT, DELETE /orgs/{orgId}/certificates/{id}` | read, replace (409 if unmanaged), delete |
| `POST /orgs/{orgId}/certificates/{id}/renew` | issue now (409 if unmanaged) |
| `GET /orgs/{orgId}/certificates/{id}/versions` | issued versions |
| `POST /orgs/{orgId}/certificates/{id}/versions/upload` | add an uploaded version to an unmanaged certificate (409 if managed) |
| `GET /orgs/{orgId}/certificates/{id}/versions/{vid}/download` | PEM or DER file, or zip; `key` needs `keys:export` |
| `POST /orgs/{orgId}/certificates/{id}/versions/{vid}/export` | PKCS#12 or JKS export (password in the body); needs `certs:read` and `keys:export` |
| `POST /orgs/{orgId}/certificates/{id}/versions/{vid}/revoke` | revoke an issued version for a private CA (422 for ACME, or a non-issued version; 409 if already revoked) — see [private-ca.md#revocation](private-ca.md#revocation) |
| `GET /orgs/{orgId}/certificates/{id}/attempts` | attempts with step timeline and log |
| `GET /orgs/{orgId}/certificates/{id}/manual-dns` | TXT records waiting for an operator |
| `POST /orgs/{orgId}/certificates/{id}/manual-dns/confirm` | resume the waiting attempt |
| `GET /orgs/{orgId}/rate-ledger?ca=<id>&certificate=<id>` | the CA's current rate-limit usage (`ca` required; `certificate` adds the duplicate-certificate item) — needs `certs:read`; see [certificates.md#rate-limits](certificates.md#rate-limits) |
| `GET /users` | list users |
| `PATCH /users/{id}` | disable or re-enable a user, revoking sessions |
| `GET, POST /api-keys` | list, create API keys (token shown once) |
| `DELETE /api-keys/{id}` | revoke an API key |
| `GET /role-bindings` | list role bindings (`?orgId=`, `?subjectType=` filter) |
| `POST /role-bindings` | create a role binding for a user, OIDC group, or API key |
| `DELETE /role-bindings/{id}` | delete a role binding; 409 for the last global admin |
| `GET /audit` | filtered, keyset-paginated audit events |
| `GET /audit/{id}` | one audit event; 404 (not 403) if missing or not visible to the caller |
| `GET /audit/export` | same filters, CSV, capped at 100 000 rows |
| `GET /audit/verify` | audit chain status, cached 60 s |
| `GET /clients`, `GET, POST /orgs/{orgId}/clients` | list across orgs, list, create a client (returns a one-time enrolment token) |
| `GET, PATCH, DELETE /orgs/{orgId}/clients/{id}` | read, rename/re-site, delete a client |
| `POST /orgs/{orgId}/clients/{id}/revoke` | revoke a client's agent certificate |
| `POST /orgs/{orgId}/clients/{id}/reenroll` | return a client to pending with a fresh token |
| `GET, POST /orgs/{orgId}/clients/{id}/grants` | list, create a grant |
| `GET /orgs/{orgId}/clients/{id}/hook-runs` | a client's hook runs |
| `GET, POST /orgs/{orgId}/deploy-targets/{id}/grants` | list, create a server-side grant on a deploy target |
| `PATCH, DELETE /orgs/{orgId}/grants/{id}` | change, delete a grant |
| `POST /orgs/{orgId}/grants/{id}/redeploy` | force reinstall and report |
| `GET /orgs/{orgId}/certificates/{id}/deployments` | a certificate's deployments across clients |
| `GET, POST /orgs/{orgId}/layouts` | list, create output layouts |
| `GET, PATCH, DELETE /orgs/{orgId}/layouts/{id}` | read, replace, delete a layout |
| `GET, POST /orgs/{orgId}/deploy-targets` | list, create deploy targets |
| `GET, PATCH, DELETE /orgs/{orgId}/deploy-targets/{id}` | read, replace, delete a deploy target |
| `GET, POST /orgs/{orgId}/hooks` | list, create hooks |
| `GET, PATCH, DELETE /orgs/{orgId}/hooks/{id}` | read, replace, delete a hook |
| `GET /agents/ca` | list agent CAs and the listener certificate |
| `POST /agents/ca/rotate` | rotate the agent CA |
| `POST /agents/ca/{id}/retire` | retire an agent CA |
| `GET, POST /orgs/{orgId}/channels` | list, add notification channels |
| `GET, PATCH, DELETE /orgs/{orgId}/channels/{id}` | read, update, delete a channel |
| `POST /orgs/{orgId}/channels/{id}/test` | send a test notification |
| `GET, POST /orgs/{orgId}/monitors` | list, add external TLS monitors |
| `GET, PATCH, DELETE /orgs/{orgId}/monitors/{id}` | read, update, delete a monitor |
| `POST /orgs/{orgId}/monitors/{id}/check` | check a monitor now |
| `GET /orgs/{orgId}/events` | filtered, keyset-paginated event feed |
| `POST /settings/smtp/test` | send a test email through the saved SMTP section |
| `POST /backup` | stream an encrypted database backup |
| `GET /backup/status` | backup schedule and last outcome |
| `GET /server-info` | running server version; any authenticated principal |

`GET /metrics` (not under `/api/v1`, outside the OpenAPI document, like `/crl` above) is a Prometheus scrape target, gated by Settings → Prometheus: 404 while `enabled` is false, else a bearer token (`Authorization: Bearer <token>`, constant-time compared) is required — a missing or wrong one is 401 with an empty body and `WWW-Authenticate: Bearer`. See [monitoring.md#prometheus](monitoring.md#prometheus) and [monitoring.md#metrics-reference](monitoring.md#metrics-reference).

`internal/api/client` is a generated Go client for this API (`api/oapi-codegen.client.yaml`), used by `cmd/cfctl`.

`GET /.well-known/acme-challenge/{token}` (not under `/api/v1`, on the main listener, unauthenticated) serves an http-01 key authorization as `text/plain` for a token this server is currently waiting on (`^[A-Za-z0-9_-]{1,128}$`), or 404 otherwise. It is not in the OpenAPI document.

`GET /crl/{caId}.crl` and `GET /crl/{caId}/{issuerSerial}.crl` (not under `/api/v1`, on the main listener, unauthenticated) serve a `localca` CA's CRL as `application/pkix-crl` DER with `Cache-Control: max-age=600` — the current issuer's at the first form, any issuer the CA has ever held (lower-case hex serial, `^[0-9a-f]{1,40}$`) at the second — 404 for an unknown id, a non-localca CA, `crl: false`, or an unknown issuer serial. Neither is in the OpenAPI document, matching the ACME challenge route above. See [private-ca.md#crl](private-ca.md#crl).

### Clients

`GET /orgs/{orgId}/clients` (and the cross-org `GET /clients`, like `GET /certificates`) list hosts running certforge-agent, filtered by `site`, `status` and `q` (case-insensitive substring of the client name or reported hostname), sorted by `name`, `lastSeen` or `status` (`-` prefix for descending), with `limit`/`cursor` like certificates — a `cursor` only continues the request it came from (422 otherwise). `POST /orgs/{orgId}/clients` creates a pending client and returns `ClientCreated`: the client, a one-time enrolment token shown once (`cf1.<agent URL>.<CA fingerprint>.<secret>`, valid for Settings → Agents → token lifetime; only its SHA-256 hash is stored), its expiry, and the agent listener URL. `PATCH` renames a client or moves it between sites (`siteId` null clears the site); `DELETE` only works on a pending or revoked client (409 otherwise) and removes its grants, deployments and hook runs with it. `POST .../revoke` refuses the agent's current certificate, deletes unused enrolment tokens, and closes its WebSocket (close code 4001); revoking twice is a no-op, and a revoked client can only be deleted, never re-enrolled. `POST .../reenroll` returns a non-revoked client to `pending` with a fresh token, refusing its old certificate and closing its socket; a revoked client gets 409. Org deletion is blocked by clients, layouts, deploy targets and hooks. `connected` means the agent holds a WebSocket now; `online` is `connected` or `lastSeen` within Settings → Agents → offline after, so a pull-only agent stays online while it keeps pulling. `agentCaId` is the agent CA that signed the client's current certificate (null until enrolled) — see Agent CA below for rotation and retirement. Audit log: agent actors show the client name.

### Grants and deployments

A grant assigns one certificate to one client with a delivery mode (`push` nudges the agent over its socket on every relevant change; `pull` waits for the agent's own schedule), an optional output layout, an optional deploy target, hooks in run order, and `autoRemediate`. `POST /orgs/{orgId}/clients/{id}/grants` requires the certificate, layout, deploy target and hooks to be in the client's org (422 otherwise) and at least one of layout or deploy target; one grant per client and certificate (409), and two grants on one client can never write the same path — counting live Traefik `certs/<SafeName>` files and grants still awaiting agent removal (409). `PATCH /orgs/{orgId}/grants/{id}` replaces delivery, layout, deploy target, hooks and auto-remediation (the certificate itself cannot change), re-renders the deployment and bumps the client's revision in the same transaction. `DELETE` queues the agent to remove the grant's files (Traefik YAML first) and the grant disappears once the agent reports; for a client that never enrolled or is revoked it is deleted immediately. `?force=true` skips waiting for the agent entirely and hard-deletes the grant at once — whether it is still live or already awaiting removal — audited with `forced: true`; use it once the agent is gone for good (revoking a client already does this automatically for its removal-pending grants). `POST .../redeploy` is a force reinstall: it bumps the grant's `redeploySeq` (the agent is level-triggered on the assignment, so an unchanged version and file list would otherwise never redeploy on their own), marks the deployment `pending` and bumps the revision so the agent rewrites every file, re-runs its hooks, and reports again — whether or not anything actually changed. `GET /orgs/{orgId}/certificates/{id}/deployments` lists one row per live grant of a certificate: the client (id, name, status), its connection (`clientConnected` is a live WebSocket now; `clientOnline` is the same rule as `Client.online`), the grant's `delivery`, its layout and deploy target (id and name, both null when the grant has none of that kind), and the deployment's state, expected/installed file digests and any error. `GET /orgs/{orgId}/clients/{id}/hook-runs` paginates a client's hook executions (newest first, `stdout`/`stderr` capped at 8 KiB) the same way certificate lists do.

### Delivery

Layouts, deploy targets and hooks are how a grant reaches the agent host. `GET, POST, PATCH, DELETE /orgs/{orgId}/layouts[/{id}]` manage output layouts (`OutputFile` path, format, PEM parts, owner/group/mode); `GET, POST, PATCH, DELETE /orgs/{orgId}/deploy-targets[/{id}]` manage deploy targets, whose `config` is validated against the type's JSON Schema from `GET /meta/schemas` under `deployTargets` (currently `traefik`, config `dir`, `pathPrefix`, `defaultCert`, `stores`; `vault-kv`, server-run, see deploy-targets.md); a type's `runsOn` (`server`, `agent`, or `either` — then `DeployTargetInput.runsOn` picks one) and `type` are immutable after create (422), a secret config field is write-only (never read back; `DeployTarget.storedSecrets` names which hold a value; omitted or `__unchanged__` keeps it, `""` clears an optional one, changing a URL while a secret is kept needs it re-entered), every URL in `config` is checked against the URL policy (loopback allowed on an agent target, gated by `allowLoopbackUrls` on a server one), and a resolved config needing the certificate's private key needs `keys:export` on every create and update (see deploy-targets.md#secrets); `GET, POST, PATCH, DELETE /orgs/{orgId}/hooks[/{id}]` manage hooks (`argv[0]` an absolute executable path, never run through a shell; an agent only runs a hook whose `argv[0]` is in its own `CF_HOOK_ALLOW`). A layout's or deploy target's `PATCH` re-renders every grant using it and bumps the affected clients' revisions in the same transaction (409 if that would make two of a client's grants write the same path); deleting any of the three is blocked (409) while a grant (including one awaiting agent removal) still uses it, naming up to five `client/certificate` pairs.

### Agent CA

`GET /agents/ca` (global `settings:read`) lists every internal agent CA — status (`active`, `retiring`, `retired`), fingerprint, subject, validity, and the count of unexpired active-client certificates it issued — plus the agent listener's own current certificate. `POST /agents/ca/rotate` (global `settings:write`) creates a new active CA and marks the previous one `retiring`; both stay trusted while online agents receive the new trust bundle and move over as they renew. `POST /agents/ca/{id}/retire` stops trusting a `retiring` CA; it 409s for the active CA or while it has issued any active, unexpired agent certificate.
