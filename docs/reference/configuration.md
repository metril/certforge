# Configuration reference

Every environment variable CertForge reads, and every setting with its default and bounds. Day-to-day configuration lives in the web UI (see [Settings](../guide/settings.md)); the environment only carries what the server needs before it can reach and decrypt its database.

## Server environment variables

Read by `certforge serve` and the other [server commands](server-cli.md). A bad value is a startup error that names the variable, never its value.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `CF_DATABASE_URL` | yes | – | Postgres URL, for example `postgres://certforge:pw@postgres:5432/certforge?sslmode=disable`. Add `&pool_max_conns=20` to size the pool (a pgx URL parameter, not a separate variable). |
| `CF_LISTEN_HTTP` | no | `:8080` | UI and API listener. It also serves `/healthz`, `/readyz`, `/metrics`, `/.well-known/acme-challenge/*`, `/crl/*` and the agent protocol under `/agent/v1`, so agents can reach it through a TLS-terminating proxy. |
| `CF_LISTEN_AGENT` | no | `:8443` | Agent listener. It serves only `/agent/v1/*` over TLS with a server certificate from the agent CA. It does not ask for client certificates: agents prove who they are with signed, sealed requests. A TLS-terminating proxy may sit in front of it, or agents may use the HTTP port instead. See [Deploying](../operations/deploying.md). |
| `CF_BASE_URL` | no | – | Public URL of the server, for example `https://certs.example.com`. Must be an absolute `http(s)` URL with a host and no credentials, query or fragment; a trailing slash is removed. The value in **Settings → General** takes precedence. |
| `CF_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn` or `error`. |
| `CF_SETUP_TOKEN` | no | – | Optional first-run setup token, at least 16 characters. When set, the setup wizard asks for it and `POST /setup/complete` returns 401 without it. Unset means setup needs no token. |
| `CF_SETUP_TOKEN_FILE` | no | – | Path to a file holding the setup token (whitespace trimmed). Set only one of the two. Never logged. |
| `CF_OIDC_ALLOW_INSECURE_ISSUER` | no | `false` | `true` lets **Settings → Authentication** accept a plain `http://` OIDC issuer on a non-loopback host. Without it, `http://` is accepted only for `localhost`, `127.0.0.0/8` and `::1`. For dev and test stacks only. Must be a boolean. |
| `CF_BACKUP_SPOOL_DIR` | no | OS temp dir | Where a backup stages each table's unencrypted CSV (in a private `0700` subdirectory, deleted when the backup ends). Never the backup directory unless you set it so. If `/tmp` is a tmpfs the staged data sits in memory; point this at a disk path for that case. If no spool can be created the backup buffers tables in memory and logs a warning. |
| `CF_ADMIN_PASSWORD` | no | – | Read only by `certforge bootstrap-admin`, as one-shot input. `serve` never reads it. See [server-cli.md](server-cli.md#bootstrap-admin). |

The container image also honours Go's standard `SSL_CERT_FILE` and `SSL_CERT_DIR` for the system trust roots the server uses when it calls out (ACME CAs, webhooks, OIDC). DNS provider credentials use their own stored values, not the server's environment. The one exception is a credential that deliberately relies on the server's own cloud identity (an instance role, for example); only a global administrator can create one. See [DNS providers](dns-providers.md).

### The encryption key

The encryption key (called KEK, for key-encryption key, in variable names) encrypts every private key and secret in the database. The server will not start without one. Set exactly one of `CF_KEK`, `CF_KEK_FILE` and `CF_KEK_VAULT_ADDR`; a mix is a startup error naming the variables.

Generate a static key:

```bash
head -c 32 /dev/urandom | base64
```

Store a copy outside the server before you issue anything. Losing the key means losing every private key and secret in the database, and every backup. The server derives a key id from the key, stores it with every encrypted row, and checks a sealed root secret and a canary at startup. After the first boot a wrong key cannot decrypt the root secret and the server refuses to start. `/readyz` reports `kek: failed` in the narrower case where the root decrypts but the canary does not. Only a fresh database accepts whatever key it is first given. See [Security model](../operations/security-model.md) for how the key is used.

In a container, a `CF_KEK_FILE` must be readable by uid 65532: `chown 65532 kek && chmod 0400 kek`. The contents of every `_FILE` variable are trimmed of surrounding whitespace.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `CF_KEK` | one of `CF_KEK`, `CF_KEK_FILE`, `CF_KEK_VAULT_ADDR` | – | 32 random bytes, base64 (standard or URL alphabet, padded or not). |
| `CF_KEK_FILE` | see above | – | Path to a file holding the key: base64, or exactly 32 raw bytes. |
| `CF_KEK_VAULT_ADDR` | see above | – | Vault or OpenBao address. Selects a Transit-backed key instead of a static one; see [Vault guide](../guide/vault.md#transit-kek). |
| `CF_KEK_VAULT_TRANSIT_KEY` | with `CF_KEK_VAULT_ADDR` | – | Transit key name. |
| `CF_KEK_VAULT_MOUNT` | no | `transit` | Transit secrets engine mount. |
| `CF_KEK_VAULT_NAMESPACE` | no | – | Vault Enterprise namespace. |
| `CF_KEK_VAULT_CA_FILE` | no | – | PEM bundle of extra CAs to trust for Vault's TLS. It adds to the system pool; verification is never disabled. |
| `CF_KEK_VAULT_TOKEN` | one auth method | – | Vault token (token auth). |
| `CF_KEK_VAULT_TOKEN_FILE` | see above | – | Path to a file holding the token. Set only one of the two. |
| `CF_KEK_VAULT_ROLE_ID` | with a secret id | – | AppRole role id. |
| `CF_KEK_VAULT_SECRET_ID` | with the role id | – | AppRole secret id. |
| `CF_KEK_VAULT_SECRET_ID_FILE` | see above | – | Path to a file holding the secret id. Set only one of the two. |

Choose one auth method for Vault: a token, or a role id plus a secret id. Setting both, or neither, is a startup error.

#### Previous key

During a key rotation, the old key stays configured so rows that re-encryption has not reached yet can still be read. At most one static and one Vault previous key may be set. A previous key that names the same key as the active one is a startup error. For the steps, see [Key management](../operations/key-management.md).

| Variable | Default | Meaning |
|---|---|---|
| `CF_KEK_PREVIOUS` | – | Older static key, base64. |
| `CF_KEK_PREVIOUS_FILE` | – | Path to a file with the older static key. Set only one of the two. |
| `CF_KEK_PREVIOUS_VAULT_ADDR` | – | Older Vault Transit key's address, in place of the static previous key. |
| `CF_KEK_PREVIOUS_VAULT_TRANSIT_KEY` | – | Its Transit key name. Required with the address. |
| `CF_KEK_PREVIOUS_VAULT_MOUNT` | `transit` | Its Transit mount. |
| `CF_KEK_PREVIOUS_VAULT_NAMESPACE` | – | Its namespace. |
| `CF_KEK_PREVIOUS_VAULT_CA_FILE` | – | Extra CAs for its TLS. |
| `CF_KEK_PREVIOUS_VAULT_TOKEN`, `CF_KEK_PREVIOUS_VAULT_TOKEN_FILE` | – | Its token, or a file holding it. |
| `CF_KEK_PREVIOUS_VAULT_ROLE_ID`, `CF_KEK_PREVIOUS_VAULT_SECRET_ID`, `CF_KEK_PREVIOUS_VAULT_SECRET_ID_FILE` | – | Its AppRole credentials. |

## Agent environment variables

Read by `certforge-agent` on the client host. Meaning, defaults and the hook environment are explained in [agent.md](agent.md); this is the complete list.

| Variable | Default | Meaning |
|---|---|---|
| `CF_AGENT_DATA` | `/data` | Directory for the agent's identity and state. |
| `CF_AGENT_TOKEN` | – | One-time enrolment token. |
| `CF_AGENT_TOKEN_FILE` | – | Path to a file holding the token. The agent waits if the file does not exist yet. |
| `CF_WRITE_ALLOW` | empty (no writes) | Colon-separated absolute directories the agent may write to. `/` is refused. |
| `CF_HOOK_ALLOW` | empty (no hooks) | Colon-separated absolute paths of executables a hook may run. |
| `CF_AGENT_PULL_INTERVAL` | `0` | Pull-mode period, a Go duration of at least `1m`, or `0` for socket only. |
| `CF_AGENT_HTTP01_LISTEN` | off | `host:port` to serve http-01 challenges on. |
| `CF_AGENT_TLSALPN_LISTEN` | off | `host:port` to serve tls-alpn-01 challenges on. |
| `CF_AGENT_TRANSPORT` | `auto` | `auto`, `mtls` or `proxy`: which TLS roots the agent trusts for the server. |
| `SSL_CERT_FILE` | system | Extra trust root, for example the CA of a private reverse proxy. |

A hook also receives `CF_GRANT_ID`, `CF_CERTIFICATE_NAME`, `CF_VERSION_ID`, `CF_FINGERPRINT` and `CF_FILES` (colon-separated paths).

## cfctl environment variables

| Variable | Meaning |
|---|---|
| `CFCTL_URL` | Server URL. |
| `CFCTL_TOKEN` | API key. |
| `XDG_CONFIG_HOME`, `HOME` | Locate the config file `cfctl/config.json`. |

See [cfctl.md](cfctl.md#configuration).

## Compose variables

The compose files read a few variables of their own. They are not read by the server; see [Deploying](../operations/deploying.md).

| Variable | Default | Meaning |
|---|---|---|
| `CF_DB_PASSWORD` | `certforge` | Postgres password. |
| `CF_HTTP_PORT` | `8080` | Host port for the UI and API. |
| `CF_AGENT_PORT` | `8443` | Host port for the agent listener. Optional when agents use a proxy. |
| `CF_VERSION` | `latest` | Image tag in `compose.release.yaml`. Pin it in production. |

## Settings

Live configuration is stored in the database and edited in **Settings** without a restart. Each Settings page is a section with a schema; `GET /api/v1/settings/{section}` returns `{section, schema, value, stored}` and `PUT` validates the value against the schema (422 on failure). An unset section returns its defaults. A property marked secret is write-only: it is stored encrypted, never returned, and `GET` lists the ones that hold a value in `storedSecrets`. On `PUT`, `__unchanged__` or leaving the field out keeps the stored secret, and `""` clears it.

The sections are `general`, `authentication`, `issuance_defaults`, `issuance`, `agents`, `backup`, `smtp`, `notifications`, `prometheus` and `vault`. Settings are global; **Issuance defaults** can also be set per organization.

### General

**Settings → General** (`general`).

| Field | Default | Meaning |
|---|---|---|
| **Base URL** (`baseUrl`) | – | Public URL people and agents use to reach CertForge. Must match `https?://host[/path]`. Takes precedence over `CF_BASE_URL`. |

### Authentication

**Settings → Authentication** (`authentication`): single sign-on, sessions, login limits and API key limits.

| Field | Default | Bounds | Meaning |
|---|---|---|---|
| **Single sign-on** (`enabled`) | off | – | Shows the single sign-on button on the login page. Needs **Issuer URL** and **Client ID**. |
| **Issuer URL** (`issuer`) | – | `http(s)` URL | The OIDC issuer. CertForge reads `/.well-known/openid-configuration` from it. Must be `https://` unless the host is loopback or `CF_OIDC_ALLOW_INSECURE_ISSUER` is set. |
| **Client ID** (`clientId`) | – | max 200 characters | The client registered for CertForge. Redirect URI: `<base URL>/api/v1/auth/oidc/callback`. |
| **Client secret** (`clientSecret`) | – | max 1024 characters | Write-only. Leave empty for a public client (PKCE only). |
| **Scopes** (`scopes`) | `openid profile email groups` | must include `openid` | Requested scopes. |
| **Groups claim** (`groupsClaim`) | `groups` | max 128 characters | ID token claim listing the user's groups. A dotted path such as `realm_access.roles` reads a nested claim; a top-level claim whose name contains a dot wins over the path. Group role bindings match these. |
| **Session lifetime (hours)** (`sessionTtlHours`) | 12 | 1–720 | How long a sign-in lasts. Applies to new sessions. |
| **Trusted proxies** (`trustedProxies`) | none | addresses or CIDRs | Reverse proxies whose `X-Forwarded-For` is believed. The audit log and login rate limit use the resulting client address. |
| **Login rate limit (per minute)** (`loginRatePerMinute`) | 10 | ≥ 0 | Login attempts per client address per minute. `0` disables the limit. |
| **Login rate limit burst** (`loginBurst`) | 5 | ≥ 1 | Attempts allowed in one burst before the per-minute rate applies. |
| **API key maximum lifetime (days)** (`apiKeyMaxLifetimeDays`) | 0 | 0–3650 | Longest lifetime a new API key may have; an expiry is then required. `0` is unlimited. Existing keys are unaffected. |
| **Active API keys per user** (`apiKeyMaxActivePerUser`) | 50 | 0–100000 | Most active keys one user may hold. `0` is unlimited. Creating more returns 409. |

**Test connection** fetches the issuer's discovery document and signing keys without logging in. **Group mappings** are role bindings with subject type `oidc_group`; see [Access](../guide/access.md).

### Access

**Settings → Access** has no settings section. It manages users, role bindings and API keys: see [Access](../guide/access.md).

### Issuance defaults

**Settings → Issuance defaults** (`issuance_defaults`). A **Scope** control switches between **Global** and **Organization**. The most specific level wins: certificate, then organization, then global, then the built-in value. A null field inherits. Changing a default takes effect at the next renewal of every certificate that inherits it.

| Field | Built-in value | Bounds | Meaning |
|---|---|---|---|
| **Certificate authority** (`caId`) | not set | – | CA used when a certificate does not pick one. Issuance fails until one is set. |
| **ACME account** (`accountId`) | not set | – | Account for that CA. ACME CAs need one; private CAs do not. |
| **Key type** (`keyType`) | `ec256` | `ec256`, `ec384`, `rsa2048`, `rsa3072`, `rsa4096` | Shown as EC P-256, EC P-384, RSA 2048, RSA 3072, RSA 4096. |
| **Renewal** (`renewPolicy`) | percent, 33 | mode `days` or `percent`; value 1–365, at most 99 for `percent` | Renew that many **Days** before expiry, or once that **Percent** of the lifetime remains. **ARI** (`useAri`) also lets the CA suggest an earlier window. |
| **Preferred chain** (`preferredChain`) | none | – | Issuer common name of the alternate chain to prefer. |
| **Reuse key** (`reuseKey`) | off | – | Keep the private key across renewals. |
| **Must-Staple** (`mustStaple`) | off | – | Request the OCSP must-staple extension. |
| **Propagation timeout** (`propagationSeconds`) | provider default | 0–3600 | How long DNS-01 waits for TXT records. `0` or unset uses each DNS provider's own default. |
| **Resolvers** (`resolvers`) | system | `host` or `host:port` | Resolvers used for propagation checks. |
| **Catch-all verification rules** (`verificationRules`) | none | – | How names are validated. A lower level's list replaces the higher level's list entirely. Each rule: `match`, `method` (`dns-01` or `manual-dns`), optional `dnsCredentialId`, `propagationSeconds` (0–3600), `resolvers`, `cnameAliasZone`. |

### Issuance

**Settings → Issuance** (`issuance`): CAA checking and a local record of the CA's own ACME rate limits. Unlike issuance defaults, these do not inherit down to organizations or certificates. Set a limit to `0` to disable it; each is bounded 0–100000.

| Field | Default | Counted per | Meaning |
|---|---|---|---|
| **Check CAA records** (`caaCheck`) | on | – | Walk each name's CAA record set before ordering; fail fast when none authorizes the CA. |
| **Certificates per registered domain per week** (`rateLimits.certsPerRegisteredDomainPerWeek`) | 50 | registered domain | Across every certificate. |
| **Duplicate certificates per week** (`rateLimits.duplicateCertsPerWeek`) | 5 | exact set of names | |
| **Failed validations per hour** (`rateLimits.failedValidationsPerHour`) | 5 | registered domain | |
| **New orders per 3 hours** (`rateLimits.newOrdersPer3Hours`) | 300 | CA | |

The defaults match Let's Encrypt's published limits; a custom or staging CA may need different values. The usage report shows `enforced: false` for a staging preset. See [Certificates](../guide/certificates.md#rate-limits).

### Agents

**Settings → Agents** (`agents`). The same page lists the agent CAs and the listener certificate; see [Key management](../operations/key-management.md#agent-ca-rotation).

| Field | Default | Bounds | Meaning |
|---|---|---|---|
| **Agent URL** (`agentUrl`) | `https://<CF_BASE_URL host>:8443` | `https://host[:port]`, no path | Where agents connect. Written into every enrolment token. When agents go through a proxy, enter the proxy's URL. Its host is always on the listener certificate. Only new enrolments pick up a change. |
| **Listener names** (`listenerNames`) | the `CF_BASE_URL` host and `localhost` | up to 20 entries, 253 characters each, DNS names or IPs | Extra names on the agent listener's certificate. Saving this section re-issues the certificate at once. |
| **Enrolment token lifetime (hours)** (`tokenTtlHours`) | 24 | 1–720 | How long a new client's one-time token stays usable. |
| **Require approval** (`requireApproval`) | on | – | An agent that presents a valid token waits for an administrator to approve its verification code. Off means a valid token alone enrols the agent. See [Clients](../guide/clients.md#approval). |
| **Approval window (hours)** (`pendingTtlHours`) | 24 | 1–168 | How long a request waits for a decision, and then how long an approved agent has to collect its certificate. At most 50 requests wait per organization. |
| **Agent certificate lifetime (days)** (`agentCertDays`) | 90 | 7–365 | Lifetime of an agent's identity certificate; agents renew at two thirds. |
| **Heartbeat interval (seconds)** (`heartbeatSeconds`) | 60 | 15–3600 | How often agents report installed files for drift detection. |
| **Offline after (seconds)** (`offlineAfterSeconds`) | 180 | 30–86400 | A client not seen for this long shows as offline. Must be longer than the heartbeat interval. |

### Backups

**Settings → Backups** (`backup`). See [Backup and restore](../guide/backup.md).

| Field | Default | Bounds | Meaning |
|---|---|---|---|
| **Schedule** (`schedule`) | off | `off`, `daily`, `weekly` | How often an encrypted backup is written to disk. |
| **Retain count** (`retainCount`) | 7 | 1–90 | Scheduled backup files kept before the oldest is deleted. |
| **Directory** (`directory`) | – | absolute path, max 1024 characters | Where scheduled backups are written. Required once the schedule is not off. It must exist and be writable; saving creates and removes a probe file. |

### SMTP section

**Settings → Integrations → Email (SMTP)** (`smtp`): the server CertForge uses for email notification channels.

| Field | Default | Bounds | Meaning |
|---|---|---|---|
| **Host** (`host`) | – | max 253 | SMTP server hostname. |
| **Port** (`port`) | 587 | 1–65535 | SMTP server port. |
| **Username** (`username`) | – | max 256 | Leave empty for no authentication. A username needs **Security** `starttls` or `tls`. |
| **Password** (`password`) | – | – | Write-only. |
| **From address** (`from`) | – | email address | Required once a host is set. |
| **Security** (`security`) | `starttls` | `starttls`, `tls`, `none` | `tls` connects straight into TLS. `starttls` requires the server to offer it; there is no silent downgrade. `none` never upgrades. |
| **Timeout (seconds)** (`timeoutSeconds`) | 10 | 1–60 | Per-connection timeout. |

Changing the host or port requires re-sending the password. **Send test email** sends through the saved settings with a 10-second limit. See [Alerts](../guide/alerts.md#smtp).

### Notifications section

**Settings → Integrations → Notifications** (`notifications`): behaviour shared by every notification channel.

| Field | Default | Bounds | Meaning |
|---|---|---|---|
| **Allow loopback and link-local** (`allowLoopbackUrls`) | off | – | Lets webhook, ntfy and Home Assistant channels, and external monitors, target loopback and link-local hosts. Private-network (RFC 1918) hosts are always allowed. It also applies to DNS credential URL fields. Off is the SSRF protection. |
| **Expiry warning (days)** (`expiryWarningDays`) | 7 | 1–60 | Days before a certificate version expires that a `cert.expiring` event is raised. |
| **Renewal failure threshold** (`failureThreshold`) | 3 | 1–10 | Consecutive renewal failures before `cert.renewal_failed` is raised, at most once per day. |

### Prometheus section

**Settings → Integrations → Prometheus** (`prometheus`). See [Monitoring](../operations/monitoring.md).

| Field | Default | Bounds | Meaning |
|---|---|---|---|
| **Enabled** (`enabled`) | off | – | Serves `GET /metrics` when on; 404 when off. |
| **Bearer token** (`bearerToken`) | – | 16–256 characters | The scraper sends it as `Authorization: Bearer <token>`. Write-only. Required once enabled. |

### Vault section

**Settings → Integrations → Vault** (`vault`): used by private CAs backed by Vault PKI and by the `vault-kv` deploy target. The Transit encryption key is configured by environment variables above, not here. See [Vault guide](../guide/vault.md#integrations).

| Field | Default | Bounds | Meaning |
|---|---|---|---|
| **Address** (`address`) | – | `http(s)` URL | Vault's base URL. Required once any other field is set. |
| **Namespace** (`namespace`) | – | max 128 | Vault Enterprise namespace. Empty for open-source Vault or OpenBao. |
| **Authentication method** (`authMethod`) | `token` | `token`, `approle` | How CertForge logs in. |
| **Token** (`token`) | – | – | Write-only. Only with method `token`. |
| **Role ID** (`roleId`) | – | max 128 | Only with method `approle`. |
| **Secret ID** (`secretId`) | – | – | Write-only. Only with method `approle`. |
| **CA bundle** (`caPem`) | – | max 65536 | Extra PEM certificates trusted for Vault's TLS, added to the system pool. Verification is never disabled. |
| **Timeout (seconds)** (`timeoutSeconds`) | 10 | 1–60 | Per-request timeout. |

Changing the address or namespace requires re-sending the token (or secret id), so a stored credential is never carried to a different Vault.

## See also

- [Server commands](server-cli.md)
- [Agent reference](agent.md)
- [Key management](../operations/key-management.md)
- [Deploying](../operations/deploying.md)
