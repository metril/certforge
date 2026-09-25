# API

Base path `/api/v1`. The OpenAPI document is `api/openapi.yaml`, served at `/api/docs`.

## Authentication and permissions

Session cookie plus `X-CSRF-Token` on writes (API keys arrive in Phase 2). Each operation checks one permission for `{orgId}`:

| Permission | Operations | Roles |
|---|---|---|
| `cas:read` / `cas:write` | CA presets and CAs / add, edit, delete CAs | all / global admin |
| `accounts:read` / `accounts:write` | ACME accounts | all / admin, org-admin, operator |
| `dnscreds:read` / `dnscreds:write` | DNS credentials (never with secrets), test | all / admin, org-admin, operator |
| `certs:read` | defaults, certificates, versions, attempts, manual-dns records, PEM without key | all |
| `certs:write` | org defaults, create, edit, delete certificates | admin, org-admin, operator |
| `certs:issue` | renew now, confirm manual-dns | admin, org-admin, operator |
| `keys:export` | download `key` or `combined` (audited) | global admin |

## Errors

Errors are `application/problem+json` (RFC 9457) with `title` and `detail`. 401 unauthenticated, 403 missing permission, 404 not found in this org, 409 in use or nothing to confirm, 422 invalid input (the title names the field), 502 the CA rejected the request (detail carries the ACME problem type).

## Lists

`GET /orgs/{orgId}/certificates` takes `status`, `q` (case-insensitive substring of the name or any certificate name), `sort` (`name`, `notAfter`, `nextRenewAt`, `status`; `-` prefix for descending), `limit` (1–500, default 50) and `cursor`, and returns `{items, nextCursor}`; pass `nextCursor` back unchanged, it is null on the last page. The small collections (CAs, accounts, DNS credentials, versions, attempts, manual-dns records) return plain arrays.

## Write-only secrets

Secret fields (`eabHmac`, DNS credential fields marked `secret: true`) are never returned. On update, `__unchanged__` keeps the stored value. Settings sections follow the same rule; GET /settings/{section} returns storedSecrets. A field whose schema property is `serverPath: true` (usually a name ending `_FILE` or `_PATH`, plus a handful of fields overridden individually where the name doesn't follow that convention, such as infoblox's `INFOBLOX_CA_CERTIFICATE`) is rejected outright with 422: it names a path on lego's own host filesystem, which the API has no way to accept from a caller. Most such providers also have an inline field for the same material (used instead); a provider whose only field is a server path has no inline alternative and is marked `unsupported: true` in its schema — create/update return 422 for it until file-backed credentials arrive in Phase 5 (currently `transip` and `hyperone`). `GET /meta/schemas` still lists an unsupported provider (for the UI to grey it out), it just can't be configured yet.

`POST .../dns-credentials/{id}/test` never echoes a config value: a provider error is redacted before it reaches the response, the audit log, or (when the credential is later used for real issuance) an attempt's `lastError` — matched raw, URL-query-escaped, URL-path-escaped, and JSON-string-escaped, longest value first so a short value can't land inside and fragment a longer one. The call is bounded and gated: past a fixed timeout it answers `{ok:false, error:"timed out"}` while cleanup keeps running in the background (still counted against the concurrency limit until it finishes), and at most 2 tests run at once server-wide — beyond that it returns 503 with `Retry-After`.

## Endpoints

| Method and path | Purpose |
|---|---|
| `GET /meta/ca-presets` | CA presets with directory URL and `requiresEab` |
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
