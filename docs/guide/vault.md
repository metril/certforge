# Vault

CertForge can use HashiCorp Vault or OpenBao in three ways: to hold the server's encryption key (Transit), to issue certificates from a private CA (PKI), and to store deployed certificates (KV). Each way needs different permissions, so grant only what you use.

| Use | Where you set it up | Needs |
|---|---|---|
| Encryption key in Transit | Environment variables | A Transit key |
| Vault PKI private CA | **Settings → Integrations → Vault**, then a CA under **Issuers** | A PKI mount and role |
| Vault KV deploy target | **Settings → Integrations → Vault**, then a target under **Delivery** | A KV v2 mount |

## Before you start

- You need the `settings:write` permission (global admin) to change **Settings → Integrations → Vault**.
- Vault must be reachable from the CertForge server. TLS is always verified. You can add extra trusted roots, but you cannot turn verification off.

## Integrations

This connection serves Vault PKI CAs and Vault KV targets. It does not serve the Transit encryption key, which is set by environment variables. See [Transit KEK](#transit-kek).

1. Open **Settings → Integrations** and find **Vault**.
2. Enter **Address**, for example `https://vault.example.com:8200`.
3. Pick an **Authentication method**: `token` or `approle`.
4. Enter the secret for that method. See [AppRole](#approle) for the second option.
5. Select **Test connection**. A green **Connected** chip shows the token's lifetime (`TTL`), the Vault version and the token's policies. A red **Failed** chip shows the reason. Nothing is saved by a test.
6. Select **Save**.

| Field | What it does | Default |
|---|---|---|
| **Address** | Vault's base URL. Required once any other field is set. | Empty |
| **Namespace** | Vault Enterprise namespace. Leave empty for open-source Vault or OpenBao. | Empty |
| **Authentication method** | `token` or `approle`. | `token` |
| **Token** | A Vault token, for `token`. Secret. | Empty |
| **Role ID** | The AppRole role id, for `approle`. | Empty |
| **Secret ID** | The AppRole secret id, for `approle`. Secret. | Empty |
| **CA bundle** | PEM certificates to trust for Vault's TLS, added to the system roots. | Empty |
| **Timeout (seconds)** | Per-request timeout, 1 to 60. | `10` |

Secrets show **Stored** after saving and are never shown again. If you change **Address** or **Namespace**, you must enter the **Token** (or **Secret ID**) again. This stops a credential following the section to a different Vault. The first save is always allowed.

CertForge logs in once and keeps the session alive. A renewable token is renewed at half its remaining lifetime. An AppRole session logs in again instead. Connection errors and 5xx answers are retried up to 3 times.

## AppRole

Use AppRole for a connection that can be rotated without a long-lived token.

1. In Vault, create a role with a policy limited to the features you use. See [Policy needs](#policy-needs).
2. In CertForge, set **Authentication method** to `approle`.
3. Enter the **Role ID** and **Secret ID**.
4. Select **Test connection**, then **Save**.

Pick a `secret_id_ttl` that matches how often you will replace the secret id. CertForge keeps the token alive by logging in again. Vault cannot renew a secret id.

## Transit KEK

Vault Transit can hold the server's key-encryption key (KEK) instead of a static `CF_KEK`. The KEK protects every secret CertForge stores. With Transit, the key never leaves Vault. The server asks Vault to wrap and unwrap its data key.

This is startup configuration, not a setting. The server needs its key before it can read the database. Set `CF_KEK_VAULT_ADDR` and the other `CF_KEK_VAULT_*` variables. They are listed in [the configuration reference](../reference/configuration.md#the-encryption-key). Set only one of `CF_KEK`, `CF_KEK_FILE` and `CF_KEK_VAULT_ADDR`.

1. In Vault, enable Transit and create a key:

   ```sh
   vault secrets enable transit
   vault write -f transit/keys/certforge
   ```

2. Create a policy for the key. See [Policy needs](#policy-needs).
3. Set these variables on the server:

   ```sh
   CF_KEK_VAULT_ADDR=https://vault.example.com:8200
   CF_KEK_VAULT_TRANSIT_KEY=certforge
   CF_KEK_VAULT_TOKEN_FILE=/run/secrets/vault_token
   ```

   `CF_KEK_VAULT_MOUNT` defaults to `transit`. Use `CF_KEK_VAULT_ROLE_ID` with `CF_KEK_VAULT_SECRET_ID` or `CF_KEK_VAULT_SECRET_ID_FILE` for AppRole. Set exactly one auth method.

4. Start the server.

At startup the server logs in and calls Vault to confirm it is reachable. An unreachable Vault stops startup at once with a clear error. When Transit holds the key, **Settings → Integrations** shows an **Encryption key** line with the Vault address.

Rotating the Transit key inside Vault does not change the key id CertForge stamps on stored data. To re-encrypt data under a new key version, see [Key management](../operations/key-management.md).

**Moving an existing install to Transit.** Derived keys, such as the audit chain's, come from a sealed root secret that was first seeded from the static KEK. An install that has already dropped its static KEK cannot seed that secret and will not start. Set the original `CF_KEK` once, until the root secret is sealed, then switch to Transit. See [Security model](../operations/security-model.md).

## PKI

A **Vault PKI** private CA signs certificates through Vault's PKI secrets engine. The signing key never leaves Vault. Configure the [connection](#integrations) first. Creating a CA before that is refused with "configure Settings → Integrations → Vault first".

1. Open **Issuers** and add a CA of kind **Vault PKI**.
2. Enter **Mount** (default `pki`), **Role**, and optionally **TTL**.
3. Save.

| Field | What it does | Default |
|---|---|---|
| **Mount** | The PKI secrets engine mount. | `pki` |
| **Role** | The Vault PKI role to sign against. Required. | None |
| **TTL** | Leaf validity as a duration, from `1h` to `19800h`. Vault's own limits still apply. | The role's `max_ttl` |

On create, CertForge reads the mount's CA certificate (`<mount>/cert/ca`) and keeps it as the CA's trust bundle and validity dates. It does not read it again. If you replace the CA inside Vault, create a new CertForge CA pointed at it. Editing a CA changes **Mount**, **Role** and **TTL** only and does not contact Vault.

Each issuance sends the CSR to `<mount>/sign/<role>`. CertForge checks that the returned certificate matches the CSR's public key. Revoking a certificate calls `<mount>/revoke`. Vault publishes its own CRL, so CertForge has no local CRL for this kind. Vault PKI has no ACME directory, so there is no ACME renewal information to poll.

The Vault role needs at least:

- `allow_any_name: true`, or domain rules that cover every name you will request (`allowed_domains` with `allow_subdomains` or `allow_glob_domains`);
- `allow_ip_sans: true`, if any certificate carries an IP address;
- `max_ttl` at least as long as the CA's **TTL**, or the longest leaf you will issue without one.

See [Issuers](issuers.md) for issuing, trust bundles and revocation.

## KV

A **Vault KV** deploy target writes a certificate's files as one document in a KV v2 secrets engine. It uses the [connection](#integrations) above and has no credential of its own. Its path template is checked before each write. It cannot start with `/` or contain `..`, and may use only letters, digits and `. _ / -`. CertForge only writes. It never reads a path back, so `read` is not needed. See [Delivery](delivery.md#vault-kv) for the target's fields.

## Policy needs

Grant the narrowest policy for what you use.

| Feature | Path | Capabilities |
|---|---|---|
| Transit encrypt, decrypt and rewrap | `<mount>/encrypt/<key>`, `<mount>/decrypt/<key>`, `<mount>/rewrap/<key>` | `update` |
| Transit key info | `<mount>/keys/<key>` | `read` |
| KV v2 write | `<mount>/data/<path>` | `create`, `update` |
| PKI sign | `<mount>/sign/<role>` | `update` |
| PKI revoke | `<mount>/revoke` | `update` |
| PKI read CA | `<mount>/cert/ca` | `read` |
| Token renewal | `auth/token/lookup-self`, `auth/token/renew-self` | `read`, `update` (usually in the default policy) |

An example policy for Transit and KV:

```hcl
path "transit/encrypt/certforge" { capabilities = ["update"] }
path "transit/decrypt/certforge" { capabilities = ["update"] }
path "transit/rewrap/certforge"  { capabilities = ["update"] }
path "transit/keys/certforge"    { capabilities = ["read"] }
path "secret/data/certforge/*"   { capabilities = ["create", "update"] }
```

## OpenBao

OpenBao uses the same API for token and AppRole login, Transit, KV v2 and PKI. CertForge supports it the same way as Vault. The automated tests run against HashiCorp Vault only, so OpenBao is untested. If something behaves differently, please report it.

## Common problems

**Test connection says Failed.** Read the reason on the chip. Check **Address**, the network path, **Namespace** and the credentials. For a private CA, add its certificate to **CA bundle**. A wrong password or token is reported as a failed test, not an error page.

**Save fails with "re-enter the token".** You changed **Address** or **Namespace** but left the secret alone. Enter the **Token** or **Secret ID** again.

**The server will not start with Transit.** Startup could not reach Vault or log in. Check `CF_KEK_VAULT_ADDR`, the auth variables and the CA file. The error names the variable and never prints a secret.

**Creating a Vault PKI CA says to configure Vault first.** Save the connection under **Settings → Integrations → Vault**.

**A Vault KV deploy fails.** Check that the token can `create` and `update` on `<mount>/data/<path>`, and that **Mount** is a KV v2 engine. See [Delivery](delivery.md#common-problems).

**Issuing from Vault PKI fails with a role error.** The role does not allow a name or IP in the request. Widen `allowed_domains` or enable `allow_ip_sans`.

**The `/readyz` check `checks.vault` is not ok.** The connection is set but unreachable or rejected. See [Monitoring](../operations/monitoring.md).

## See also

- [Delivery](delivery.md) for the Vault KV target
- [Issuers](issuers.md) for private CAs
- [Key management](../operations/key-management.md) for rotating the encryption key
- [Configuration reference](../reference/configuration.md#the-encryption-key) for `CF_KEK_VAULT_*`
