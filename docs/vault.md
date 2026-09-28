# Vault

`internal/vault` is a small HTTP client for HashiCorp Vault, built on the
standard library (`net/http`) with no Vault SDK dependency. It backs the
Transit KEK (Phase 5), private CAs issued through Vault's PKI secrets
engine, and the `vault-kv` deploy target. The "vault" global settings
section (Settings → Integrations, `GET/PUT /api/v1/settings/vault`)
configures the address, namespace, authentication and TLS trust it uses;
`internal/vault.Provider` (Phase 5, Task 8) turns those settings into a
live, cached client.

## Transit KEK {#transit-kek}

Vault Transit can back the server's key-encryption key (KEK) in place of a
static `CF_KEK`/`CF_KEK_FILE` value. It is bootstrap configuration, set with
`CF_KEK_VAULT_*` environment variables (see `docs/configuration.md`'s KEK
table), not the `vault` settings section — the server needs a working KEK
before it can read the database, let alone the settings stored in it.

With `CF_KEK_VAULT_ADDR` set, the DEK that seals every secret is wrapped by
calling Vault's `<mount>/encrypt/<key>` and unwrapped with
`<mount>/decrypt/<key>` (`crypto.TransitWrapper`), instead of AES-256-GCM
directly over a key CertForge holds. The Transit key's own bytes never
reach the server; only opaque `vault:vN:...` ciphertext does. Its KEK id is
derived from the address, mount and key name (`crypto.TransitKEKID`), not
from Vault-side key material, so rotating the key's version inside Vault
does not change the id every encrypted blob is tagged with.

At boot, `cmd/certforge.buildKEK` logs the configured `Auth` in
(`TokenAuth` adopts its token with no network call; `AppRoleAuth` POSTs to
Vault) and calls `LookupSelf` to confirm Vault is actually reachable before
the database envelope is built at all — an unreachable Vault fails startup
immediately with a redacted error, rather than surfacing later as an opaque
decrypt failure on the first secret read. The client's renewal loop
(`Client.Start`) then keeps the token or AppRole session alive for the rest
of the process's life.

A Transit KEK cannot itself supply the bytes an existing install's derived
keys (the audit HMAC key, in particular) were built from before this KEK
type existed — see `docs/security.md#root-secret` for how the sealed root
secret decouples those derived keys from the KEK's own bytes, and why an
existing install with no static KEK at all cannot seed that root the first
time it boots on Transit.

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
