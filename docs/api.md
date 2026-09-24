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

Secret fields (`eabHmac`, DNS credential fields marked `secret: true`) are never returned. On update, `__unchanged__` keeps the stored value.

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
