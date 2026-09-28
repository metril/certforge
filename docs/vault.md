# Vault

`internal/vault` is a small HTTP client for HashiCorp Vault, built on the
standard library (`net/http`) with no Vault SDK dependency. It backs the
Transit KEK (Phase 5), private CAs issued through Vault's PKI secrets
engine, and the `vault-kv` deploy target. The "vault" global settings
section (Settings → Integrations, `GET/PUT /api/v1/settings/vault`)
configures the address, namespace, authentication and TLS trust it uses;
`internal/vault.Provider` (Phase 5, Task 8) turns those settings into a
live, cached client.

## Authentication

Two methods, chosen by which `Auth` value the client is built with:

- **Token** (`TokenAuth`): a pre-issued Vault token. `Login` is then a
  no-op; there is no login call for token auth.
- **AppRole** (`AppRoleAuth`): `RoleID` and `SecretID` are POSTed to
  `/v1/auth/<mount>/login` (mount defaults to `approle`). A request that
  gets `403` under AppRole auth logs in again once and retries once, so a
  token that expired mid-session self-heals without the caller noticing.

`Client.Start` runs a background renewal loop: a renewable token is
renewed at half its remaining TTL (`RenewSelf`); an AppRole session is
refreshed by logging in again. `Close` stops it.

## Requests

Every request carries `X-Vault-Token` and, when set, `X-Vault-Namespace`.
Connection errors and 5xx responses are retried up to 3 times with backoff
(200ms, 400ms), capped by the caller's context; 4xx is never retried. A
response body over 1 MiB is treated as an error rather than read in full.
`Client.CA` only ever adds trusted certificates to the system root pool
(`CAPEM` in `Config`/the `caPem` setting) — TLS verification is never
disabled, on this client or any other in CertForge.

Every exported method redacts the current token and, under AppRole, the
configured secretId from any error it returns (`Client.Redact`), so a
caller can log or surface that error without leaking either. Neither value
is ever written to the audit log.

## Policy needs

Grant the narrowest policy for the features actually used:

| Feature | Path | Capabilities |
|---|---|---|
| Transit encrypt/decrypt/rewrap | `<mount>/encrypt/<key>`, `<mount>/decrypt/<key>`, `<mount>/rewrap/<key>` | `update` |
| Transit key info | `<mount>/keys/<key>` | `read` |
| KV v2 write | `<mount>/data/<path>` | `create`, `update` |
| PKI sign | `<mount>/sign/<role>` | `update` |
| PKI revoke | `<mount>/revoke` | `update` |
| PKI read CA | `<mount>/cert/ca` | `read` |
| Token self-service (renewal) | `auth/token/lookup-self`, `auth/token/renew-self` | `read`/`update` (usually already default-policy) |
| Health check | `sys/health` | unauthenticated |

## OpenBao {#openbao}

OpenBao is API-compatible for every path this client uses — Transit, KV
v2, PKI, AppRole and token auth — but untested against a real OpenBao
server. If something behaves differently, please report it.
