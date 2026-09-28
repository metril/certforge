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

## Integrations {#integrations}

Settings → Integrations → Vault (`GET`/`PUT /api/v1/settings/vault`) is how
the running server itself reaches Vault or OpenBao for everything other
than the Transit KEK above: private CAs on the `vaultpki` kind and the
`vault-kv` deploy target (Phase 5B). Fields: `address` (required once
anything else is set), `namespace` (Vault Enterprise only), `authMethod`
(`token` or `approle`, default `token`), `token` or `roleId`/`secretId`
depending on the method, `caPem` (extra trust, never replaces the system
root pool) and `timeoutSeconds` (1–60, default 10).

`internal/vault.Provider` turns the section into a live `*Client`:
`Client(ctx)` builds and logs in once, then caches the result keyed by a
SHA-256 hash of the section's effective value plus its decrypted secrets —
an unrelated settings change (or none at all) reuses the cached client, and
a change to the address, auth method or credentials closes the old client's
renewal loop and builds a fresh one. `Configured(ctx)` reports whether an
address is set at all, gating a `vaultpki` CA create and the `checks.vault`
readiness entry.

`POST /api/v1/settings/vault/test` (`testVaultSettings`, needs
`settings:write`, not audited) logs in with the given settings — merging an
omitted or `__unchanged__` secret field with the value already stored — and
reports `{ok, tokenTtlSeconds, policies, version}` or `{ok: false, error}`.
It never fails with a connection or authentication problem; those come back
as `ok: false` in a 200. It fails with 422 only when the request itself is
malformed: a schema violation, an `authMethod`/secret mismatch, or the
re-entry rule below. `error`, when present, has already had the client's
own token/secretId redacted and every string value of the request itself
scrubbed from it a second time, so a role id or CA bundle echoed back by a
misbehaving Vault error message cannot leak either.

**Re-entry rule**: a `PUT` or test request that changes `address` or
`namespace` must re-send the secret field its `authMethod` needs (`token`,
or `secretId` under `approle`) — an omitted or `__unchanged__` value is 422
`"re-enter the token"`. This stops a token or AppRole secretId silently
following the section over to what may be a different Vault install. The
very first save of the section is always allowed, since there is nothing
yet to compare against.

### AppRole {#approle}

For `authMethod: approle`, create a role with a policy scoped to the
features actually used (see the table below), then set `roleId` and
`secretId` on the section. A `secret_id_ttl` matching how often the
`secretId` will be rotated is reasonable; `Client`'s renewal loop keeps the
resulting token alive between rotations by logging in again (never by
renewing a `secretId` itself, which Vault does not support).

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

## PKI {#pki}

A CA of kind `vaultpki` (`CAInput.type: vaultpki`, `config`: `mount`
default `pki`, `role`, optional `ttl`) issues and revokes through Vault's
PKI secrets engine instead of holding any key material itself — the
signing key never leaves Vault. Settings → Integrations → Vault must be
configured first; creating one before that is 422 "configure Settings →
Integrations → Vault first".

Create reads the mount's current CA certificate (`GET <mount>/cert/ca`),
which becomes the CA's `trustBundlePem` and `notBefore`/`notAfter` — a
snapshot taken at create time, not re-read on every issuance or on update
(rotating the mount's own CA in Vault needs a fresh CertForge CA pointed at
it, the same as any other out-of-band Vault change). Update only replaces
`mount`/`role`/`ttl`; it does not re-contact Vault. A Vault error at create
(an unreachable server, a mount that does not exist) is 422 with the
client's own redacted message.

Issue signs a CSR through `POST <mount>/sign/<role>` (`internal/signer/
vaultpki`): the request carries `common_name`, `alt_names`, `ip_sans` and,
when the CA's `ttl` is set, `ttl` — otherwise the role's own `max_ttl`
applies. The response's `certificate` is cross-checked against the CSR's
own public key before being trusted, and its issuing chain comes from
`ca_chain` (or `issuing_ca` when Vault returned no chain). Revoke calls
`POST <mount>/revoke` (Phase 5A Task 9 wires the revoke API route itself;
the signer method lands with this task). `vaultpki` implements no ACME
directory (`RenewalInfo` returns "not supported" — there is no ARI to
poll).

The PKI role needs, at minimum:

- `allow_any_name: true`, or domain rules covering every name CertForge
  will request (`allowed_domains` plus `allow_subdomains`/`allow_glob_domains`
  as needed).
- `allow_ip_sans: true` if any certificate will carry an IP SAN.
- `max_ttl` at least as long as the CA's configured `ttl` (or the longest
  leaf validity issued without one).
- The `sign` policy capability on `<mount>/sign/<role>` (see the table
  above), plus `read` on `<mount>/cert/ca` and `update` on `<mount>/revoke`.

## OpenBao {#openbao}

OpenBao is API-compatible for every path this client uses — Transit, KV
v2, PKI, AppRole and token auth — but untested against a real OpenBao
server. If something behaves differently, please report it.
