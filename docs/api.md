# API

Base path `/api/v1`. The OpenAPI document is `api/openapi.yaml`, served at `/api/docs`.

## Authentication and permissions

Browser sign-in: GET /auth/oidc/start (single sign-on) or POST /auth/login (local admin); both set the cf_session cookie. Session writes send X-CSRF-Token. API keys: see below. `GET /auth/methods` (public) tells a client whether single sign-on and the local admin are available. Each operation checks one permission for `{orgId}`:

| Permission | Operations | Roles |
|---|---|---|
| `cas:read` / `cas:write` | CA presets and CAs / add, edit, delete CAs | all / global admin |
| `accounts:read` / `accounts:write` | ACME accounts | all / admin, org-admin, operator |
| `dnscreds:read` / `dnscreds:write` | DNS credentials (never with secrets), test | all / admin, org-admin, operator |
| `certs:read` | defaults, certificates, versions, attempts, manual-dns records, PEM without key | all |
| `certs:write` | org defaults, create, edit, delete certificates | admin, org-admin, operator |
| `certs:issue` | renew now, confirm manual-dns | admin, org-admin, operator |
| `keys:export` | download `key` or `combined` (audited) | global admin |

### API keys

Send `Authorization: Bearer cf_<prefix>_<secret>`. Keys need no CSRF header. A key can do at most what its creator can do right now, restricted to its scopes (`certs:read` also covers orgs, sites, CAs, accounts, DNS credentials; `clients:write` covers clients read and write; `admin` is everything) and to its org when it has one. Keys stop working when revoked, expired, or when the creator is disabled. The token is returned once by `POST /api-keys`; only its SHA-256 is stored.

## Errors

Errors are `application/problem+json` (RFC 9457) with `title` and `detail`. 401 unauthenticated, 403 missing permission, 404 not found in this org, 409 in use or nothing to confirm, 422 invalid input (the title names the field), 502 the CA rejected the request (detail carries the ACME problem type).

Every operation in the served spec lists the problem responses it can return (components.responses). 429 comes with Retry-After.

## Lists

`GET /orgs/{orgId}/certificates` takes `status`, `q` (case-insensitive substring of the name or any certificate name), `sort` (`name`, `notAfter`, `nextRenewAt`, `status`; `-` prefix for descending), `limit` (1–500, default 50) and `cursor`, and returns `{items, nextCursor}`; pass `nextCursor` back unchanged, it is null on the last page. `GET /certificates` takes the same parameters across every org where you have `certs:read`; items carry `orgId`. The small collections (CAs, accounts, DNS credentials, versions, attempts, manual-dns records) return plain arrays.

`GET /audit` filters by `from`, `to` (exclusive), `actor`, `action` (exact, or a prefix ending in `.`), `resourceType`, `resourceId`, `orgId`, `q` (case-insensitive substring of action, resource, actor, IP or details); newest first; `limit` and `cursor` as elsewhere. Its `cursor` is unsigned (just base64 of a decimal id): authorization is re-derived from the caller on every request, and there is no sort/filter to bind it to since the chain has one order (id). `GET /audit/export` streams the same filters as `Content-Type: text/csv; charset=utf-8` (no BOM), columns `id,ts,actor_type,actor_id,actor_name,action,resource_type,resource_id,org_id,ip,details`, at most 100 000 rows; a cell a spreadsheet would read as a formula gets a leading apostrophe. The `X-Audit-Truncated` response header is `true` when the cap was hit. A query error partway through does not truncate the file silently: a final row `#error,export interrupted; see server log` is written instead (the detail is only in the server log, never the file) — every real data row's first column is a numeric id, so this row can't be mistaken for one. Exporting is itself recorded as `audit.export`. `GET /audit/verify` walks the whole hash chain and reports `{ok, count, brokenAtId, checkedAt, headHash}`, cached 60 seconds (`Deps.AuditVerifyTTL`); it needs global `audit:read` (the chain covers every org and global events, so an org-scoped auditor gets 403 even for their own org). `GET /audit` without global `audit:read` shows only the events of orgs where you have `audit:read`; global events (no org) need global `audit:read`.

## Write-only secrets

Secret fields (`eabHmac`, DNS credential fields marked `secret: true`) are never returned. On update, `__unchanged__` keeps the stored value. Settings sections follow the same rule; GET /settings/{section} returns storedSecrets. A field whose schema property is `serverPath: true` (usually a name ending `_FILE` or `_PATH`, plus a handful of fields overridden individually where the name doesn't follow that convention, such as infoblox's `INFOBLOX_CA_CERTIFICATE`) is rejected outright with 422: it names a path on lego's own host filesystem, which the API has no way to accept from a caller. Most such providers also have an inline field for the same material (used instead); a provider whose only field is a server path has no inline alternative and is marked `unsupported: true` in its schema — create/update return 422 for it until file-backed credentials arrive in Phase 5 (currently `transip` and `hyperone`). `GET /meta/schemas` still lists an unsupported provider (for the UI to grey it out), it just can't be configured yet.

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
| `GET, POST /orgs/{orgId}/acme-accounts` | list, register accounts |
| `GET, DELETE /orgs/{orgId}/acme-accounts/{id}` | read, delete an account |
| `GET, PUT /orgs/{orgId}/issuance-defaults` | org defaults (null inherits global) |
| `GET /orgs/{orgId}/issuance-defaults/effective` | resolved defaults with sources |
| `GET, PUT /settings/issuance_defaults` | global defaults (settings section) |
| `GET, POST /orgs/{orgId}/dns-credentials` | list, add DNS credentials |
| `GET, PUT, DELETE /orgs/{orgId}/dns-credentials/{id}` | read, replace, delete a credential |
| `POST /orgs/{orgId}/dns-credentials/{id}/test` | create and remove a test TXT record |
| `GET, POST /orgs/{orgId}/certificates` | list, create (issues immediately) |
| `GET, PUT, DELETE /orgs/{orgId}/certificates/{id}` | read, replace, delete |
| `POST /orgs/{orgId}/certificates/{id}/renew` | issue now |
| `GET /orgs/{orgId}/certificates/{id}/versions` | issued versions |
| `GET /orgs/{orgId}/certificates/{id}/versions/{vid}/download` | PEM file or zip; `key` needs `keys:export` |
| `GET /orgs/{orgId}/certificates/{id}/attempts` | attempts with step timeline and log |
| `GET /orgs/{orgId}/certificates/{id}/manual-dns` | TXT records waiting for an operator |
| `POST /orgs/{orgId}/certificates/{id}/manual-dns/confirm` | resume the waiting attempt |
| `GET /users` | list users |
| `PATCH /users/{id}` | disable or re-enable a user, revoking sessions |
| `GET, POST /api-keys` | list, create API keys (token shown once) |
| `DELETE /api-keys/{id}` | revoke an API key |
| `GET /role-bindings` | list role bindings (`?orgId=`, `?subjectType=` filter) |
| `POST /role-bindings` | create a role binding for a user, OIDC group, or API key |
| `DELETE /role-bindings/{id}` | delete a role binding; 409 for the last global admin |
| `GET /audit` | filtered, keyset-paginated audit events |
| `GET /audit/export` | same filters, CSV, capped at 100 000 rows |
| `GET /audit/verify` | audit chain status, cached 60 s |
