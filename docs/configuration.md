# Configuration

CertForge is configured from the web UI. The environment only carries what the server needs before it can reach and decrypt its database.

## Bootstrap environment variables

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `CF_DATABASE_URL` | yes | – | Postgres URL, for example `postgres://certforge:pw@postgres:5432/certforge?sslmode=disable` |
| `CF_KEK` | one of these two | – | Key-encryption key: 32 random bytes, base64 |
| `CF_KEK_FILE` | one of these two | – | Path to a file with the KEK (base64, or exactly 32 raw bytes) |
| `CF_LISTEN_HTTP` | no | `:8080` | UI and API listener |
| `CF_LISTEN_AGENT` | no | `:8443` | Agent listener: TLS with agent client certificates, serves only `/agent/v1/*`. Must be reached directly or through TCP/TLS passthrough, never a TLS-terminating proxy. |
| `CF_BASE_URL` | no | – | Public URL. The setup wizard stores its own value in Settings → General, which takes precedence |
| `CF_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error` |

## The KEK

Generate one:

```bash
head -c 32 /dev/urandom | base64
```

Losing the KEK means losing every private key and secret in the database. Store a copy outside the server before issuing anything. The server derives a KEK id from the key, stores it with every encrypted row, and checks a canary at startup. With the wrong KEK, `/readyz` reports `kek: failed`.

For `CF_KEK_FILE` in the container, the file must be readable by uid 65532: `chown 65532 kek && chmod 0400 kek`.

## Settings framework

Live configuration is stored in the `settings` table (`key`, JSON `value`, encrypted `secret`) and edited from the UI without a restart.

- Each Settings page is a **section** with a JSON Schema. `GET /api/v1/settings/{section}` returns `{section, schema, value, stored}` (`stored` is the raw persisted document, before global-default merging, so a field showing "Default" in the UI doesn't claim a global value it never actually inherited). `PUT` takes the value object, validates it against the schema (422 on failure), and stores it under the key `section.<name>`. An unset section returns its default.
- Phase 1 sections: `general` (`baseUrl`), `backup` (`kekEscrowConfirmed`), and `issuance_defaults` (from the issuance plan).
- A section property marked "secret": true is write-only. It is stored encrypted in the secret column, never returned; GET lists which ones hold a value in storedSecrets. On PUT, "__unchanged__" or leaving the field out keeps it, "" clears it.

## Settings

Open **Settings** in the sidebar. Sections that arrive in later phases (Agents, Integrations) are shown disabled.

### General

Rendered from the server's settings schema: base URL and other server-wide values. **Save** applies immediately; no restart. Below it, **Organizations**: admins create, rename and delete orgs (the slug is permanent; "all" is reserved), and org admins manage each org's **Sites**. An org with certificates, credentials, accounts, CAs, sites, role bindings or active API keys cannot be deleted; the dialog lists them. Its issuance defaults and revoked API keys are removed with the org.

### Authentication

| Field | Meaning |
|---|---|
| Single sign-on | Shows the single sign-on button on the login page. Needs issuer and client ID. |
| Issuer URL | The OIDC issuer. CertForge reads `/.well-known/openid-configuration` from it. |
| Client ID, Client secret | The client registered for CertForge. Redirect URI: `<base URL>/api/v1/auth/oidc/callback`. The secret is write-only; leave it empty for a public client (PKCE only). |
| Scopes | Default `openid profile email groups`; must include `openid`. |
| Groups claim | ID token claim holding the user's groups (default `groups`). Group role bindings (Settings → Access) match these. |
| Session lifetime | Hours a sign-in lasts (1–720, default 12). Applies to new sessions. |
| Trusted proxies | Addresses or CIDRs of reverse proxies. `X-Forwarded-For` is believed only from these; the audit log and the login rate limit use the resulting client address. |
| Login rate limit (per minute) | Login attempts allowed per client address per minute (default 10). 0 disables the limit. |
| Login rate limit burst | Login attempts a client may make in a single burst before the per-minute rate applies (default 5, minimum 1). |
| Group mappings | Group-to-role bindings, edited on this page below the form. They are role bindings with subject type oidc_group, also listed under Settings → Access. |

**Test connection** fetches the issuer's discovery document and signing keys without logging in.

### Access

**Users** lists everyone who has signed in, plus the local admin. Admins can disable a user: their sessions end at once and their API keys stop working. Users are never deleted.

**API keys** are created with a name, scopes, optional org and expiry; the token is shown once.

**Role bindings** grant a role to a user, an OIDC group, or an API key, either in one org or globally. The last global admin binding held by a user cannot be removed.

### Issuance defaults

Two tabs: **Global** and your organization. Each field shows the value in effect and where it comes from (**Default**, **Global**, **Org**; hover the badge for the chain). Turn on **Override** to set a value at this level; **Reset to inherited** clears it. A reference that no longer exists (a deleted CA or account) shows its error next to the field.

| Field | Meaning |
|---|---|
| Certificate authority, ACME account | Used when a certificate does not pick its own |
| Key type | EC P-256, EC P-384, RSA 2048, RSA 3072, RSA 4096 |
| Renewal | **Days** before expiry, or **Percent**: renew once that share of the certificate's lifetime remains; **ARI** lets the CA suggest the window |
| Preferred chain | Root common name to prefer when the CA offers alternates |
| Reuse key, Must-Staple | Keep the key across renewals; request OCSP Must-Staple |
| Propagation wait, Resolvers | DNS-01 wait time and the resolvers used to check it |

Changing a default takes effect at the next renewal of every certificate that inherits it.

### Issuance

Global CAA checking and a local record of the CA's own ACME rate limits (section `issuance`; unlike Issuance defaults, above, these do not inherit down to orgs or certificates).

| Field | Default | Meaning |
|---|---|---|
| Check CAA records (`caaCheck`) | on | Walk each name's CAA record set before ordering; fail fast when none authorizes the CA. |
| Certificates per registered domain per week (`rateLimits.certsPerRegisteredDomainPerWeek`) | 50 | Counted per registered domain across every certificate. 0 disables the limit. |
| Duplicate certificates per week (`rateLimits.duplicateCertsPerWeek`) | 5 | Counted per exact set of names. 0 disables the limit. |
| Failed validations per hour (`rateLimits.failedValidationsPerHour`) | 5 | Counted per registered domain. 0 disables the limit. |
| New orders per 3 hours (`rateLimits.newOrdersPer3Hours`) | 300 | Counted per CA. 0 disables the limit. |

The defaults match Let's Encrypt's own published limits; a custom or staging CA may need different values. `enforced` reports as false for a staging preset.

### Agents

Global settings for certforge-agent (Settings → Agents).

| Field | Default | Meaning |
|---|---|---|
| Agent URL (`agentUrl`) | `https://<CF_BASE_URL host>:8443` | Where agents connect. It is written into every enrolment token, and its host is always on the listener certificate. Must be `https://host[:port]`. |
| Listener names (`listenerNames`) | CF_BASE_URL host, `localhost` | Extra DNS names or IPs on the agent listener's certificate. Saving this section re-issues the listener certificate at once. |
| Enrolment token lifetime (`tokenTtlHours`) | 24 | Hours a new client's one-time token stays usable. |
| Agent certificate lifetime (`agentCertDays`) | 90 | Days an agent's client certificate is valid; the agent renews at two thirds. |
| Heartbeat interval (`heartbeatSeconds`) | 60 (min 15) | How often agents report installed files for drift detection. |
| Offline after (`offlineAfterSeconds`) | 180 | A client not seen for this long shows as offline; must exceed the heartbeat. |

The same page lists the agent CAs with rotate and retire (see operations.md → Agent CA rotation) and the listener certificate's names and expiry.

certforge-agent itself (the binary running alongside Traefik or another target) is configured by its own environment variables on the client host, not this page — in particular `CF_WRITE_ALLOW` and `CF_HOOK_ALLOW`, the directories and executables it is allowed to touch; both are empty (nothing allowed) by default. See [agent.md → Environment](agent.md#environment).

### Backup and keys

Shows the key-encryption key's status (from `/readyz`'s `kek` check) and the **KEK escrow confirmed** switch, which must be on before scheduled backups run.

### Vault section

Global settings for reaching HashiCorp Vault (or OpenBao), served by `GET/PUT /api/v1/settings/vault` (section `vault`; a web UI page arrives in Phase 5B under Settings → Integrations). Used by the Transit KEK, by private CAs backed by Vault's PKI secrets engine, and by the `vault-kv` deploy target.

| Field | Default | Meaning |
|---|---|---|
| Address (`address`) | — | Vault's base URL, e.g. `https://vault.example.com:8200`. Required once any other field below is set. |
| Namespace (`namespace`) | — | Vault Enterprise namespace. Leave empty for open-source Vault or OpenBao. |
| Authentication method (`authMethod`) | token | `token` or `approle`. |
| Token (`token`) | — | Vault token. Used, and required, only when the authentication method is `token`; write-only. |
| Role ID (`roleId`) | — | AppRole role id. Used only when the authentication method is `approle`. |
| Secret ID (`secretId`) | — | AppRole secret id. Used only when the authentication method is `approle`; write-only. |
| CA bundle (`caPem`) | — | Additional PEM-encoded certificates trusted for Vault's TLS, appended to the system root pool. Never disables verification. |
| Timeout in seconds (`timeoutSeconds`) | 10 | Per-request timeout for calls to Vault (1–60). |

`token` may only be set when `authMethod` is `token`; `roleId`/`secretId` may only be set when `authMethod` is `approle` — setting either against the wrong method is rejected. A PUT that changes `address` or `namespace` must re-send `token` (token auth) or `secretId` (AppRole), rather than relying on `__unchanged__`, since a different Vault or namespace cannot be assumed to accept the previously stored credential.

## First-run setup wizard

Until setup completes, `GET /api/v1/setup/status` returns `{"needsSetup": true}` and the UI shows `/setup`. The wizard posts to `POST /api/v1/setup/complete`:

```json
{"adminPassword": "at least 12 characters", "orgName": "Home", "orgSlug": "home", "baseUrl": "https://certs.example.com"}
```

This sets the local admin password, stores `baseUrl` in Settings → General, creates the first org, grants the local admin the global `admin` role, and logs you in. It runs once. Later calls return 409.

The `/setup` wizard walks this in four steps:

| Step | Field | Notes |
|---|---|---|
| Admin password | Admin password, Confirm password | At least 12 characters. This is the local break-glass login. |
| Base URL | Base URL | Pre-filled with the address in your browser. A warning appears if it differs, for example behind a reverse proxy. |
| Encryption key | – | Shows the server's readiness checks. The key (`CF_KEK` or `CF_KEK_FILE`) must load and pass its canary before you can continue. Fix the environment and select **Check again**. |
| First organization | Organization, Slug | The slug appears in URLs (`/o/<slug>/…`). |

**Finish setup** creates the admin and the organization, signs you in, and opens the organization.

## Break-glass: bootstrap-admin

Reset the local admin password from the server host, after first-run setup has completed. This also revokes all of that user's sessions and clears the account's disabled flag:

```bash
docker compose exec -e CF_ADMIN_PASSWORD='new long password' certforge certforge bootstrap-admin
# or
printf '%s\n' 'new long password' | certforge bootstrap-admin --password-stdin
```

Before setup completes there is no local admin to reset, and `bootstrap-admin` refuses rather than create one outside the setup wizard: complete `POST /api/v1/setup/complete` (or the `/setup` UI) first.

`CF_ADMIN_PASSWORD` is read once, by the `bootstrap-admin` subcommand only, as one-shot input for that break-glass action. It is not part of the server's configuration: `serve` never reads it.
