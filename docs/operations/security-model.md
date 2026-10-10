# Security model

This page explains what CertForge trusts, what it protects and how. It is the summary; each topic links to the page that has the steps.

## Trust boundaries
| Party | Trusted to | Not trusted to |
|---|---|---|
| The CertForge server and its database | Hold all secrets, sign agent certificates, decide who gets which certificate. | Nothing outside its own host. A compromised server can issue agent certificates and push files. |
| The encryption key (KEK) holder | Decrypt every secret. | Keep a lost key recoverable: without the key, data and backups are lost. |
| Browsers and API clients | Act within their role, organization and scopes. | Anything else. Every request is authorized again on the server. |
| Agents | Install the files they are granted, on their own host. | Run hooks or write paths the agent operator has not allowlisted. |
| A reverse proxy in front of CertForge | Terminate browser TLS. | Read, forge, replay or enrol agent traffic. See [Agent channel](#agent-channel). |
| The network | Carry bytes. | Anything. |

## Encryption key handling
- The KEK comes from `CF_KEK` (base64), `CF_KEK_FILE` or Vault Transit (`CF_KEK_VAULT_ADDR`). It is never stored in the database and never logged. Config errors never echo it. Format and variables: [Configuration](../reference/configuration.md#the-encryption-key). Transit setup: [Vault](../guide/vault.md#transit-kek). Rotation: [Key management](key-management.md).
- Each secret is sealed with its own AES-256-GCM data key, and the KEK wraps that data key. The KEK id is stored in every blob and bound as authenticated data, so a wrong key is detected before decrypting.
- At start the server unseals the root secret. With a wrong KEK it refuses to start, because anything written under a wrongly derived key would fork the audit chain. If only the later canary check fails, the server runs but `/readyz` returns `503` with `kek: failed`.
- Keep a copy of the key outside the server. Without it, backups cannot be restored.

## Root secret
Derived keys (the audit chain HMAC key, the OIDC state key, the backup stream key) come from a 32-byte root secret (`crypto.root`) through HKDF, not from the KEK directly. Rotating the KEK re-wraps the root without changing it, so derived keys stay the same and the audit chain never forks. The root is never logged or returned by the API, and is cleared from memory once the keys are derived.

## Backup encryption
- A backup archive is encrypted with a key derived from the root secret and a fresh random salt, so no two backups share a key.
- The header (format version, time, migration version, KEK ids, salt, sealed root) is plaintext so you can identify a backup without a key. Every encrypted chunk is bound to the exact header bytes, so a change anywhere makes decryption fail.
- Restore proves the configured key can unseal the archive's root before touching the database, and re-verifies the root and the key canary inside the same transaction before committing. Any failure rolls everything back. Format and steps: [Backup](../guide/backup.md). Design: [ADR 0018](../internals/adr/0018-encrypted-backup-offline-restore.md).

## Serve lock and restore
`serve` holds a shared database advisory lock for its whole life. `restore` needs it exclusively. A running server therefore blocks a restore, and a server cannot start in the middle of one.

## Agent channel
Agents work through a proxy that terminates TLS, so nothing depends on TLS to be safe.
- Each request is signed by the agent key and each response by the server's responder key. Bodies travel in a session sealed with keys from an ephemeral key exchange, so past traffic stays secret even if a key leaks later.
- Replays, tampering and reordering are rejected. A proxy can only drop or delay traffic.
- Enrolment sends no token: the agent proves it holds it. New clients wait for an administrator to approve them after comparing a verification code.
- A client certificate alone admits nothing. The server checks on every request and WebSocket message that the client is active and the certificate is its newest one, so revocation takes effect at once without a CRL.
- Protocol: [Architecture](../internals/architecture.md#agent-protocol). Threat model and reasons: [ADR 0020](../internals/adr/0020-agent-protocol-through-proxy.md).
- Clocks: agents and server must agree within 60 s. Request nonces are kept in memory, in one cache shared by both ports, which is why CertForge runs a single replica. The cache holds at most 200,000 nonces; when full the server answers an unsigned `503` and logs it. Signed agent requests are rate limited per client address (600 a minute, burst 120), and a request naming no live session is refused before its body is read.

Enrolment tokens are single use, stored only as a SHA-256 hash, and pin the agent CA fingerprint. Enrolment endpoints are rate limited per client address, separately from login.

## Agent hooks and writes
A compromised server could push any command or path to every agent, so both are off until the agent operator allows them locally. Hooks run only if `argv[0]` exactly matches an entry in `CF_HOOK_ALLOW` (never through a shell). Files are written only under directories in `CF_WRITE_ALLOW`, checked after resolving symlinks. With either variable empty, that action fails. Allow narrow executables, never a shell or interpreter. See [Agents](../guide/agents.md#hooks-and-the-allowlist).

## Notification channel secrets and URL policy
- Channel secrets (webhook URL, auth header, signing secret, Discord webhook URL, ntfy token, Home Assistant webhook id, SMTP password) are sealed, never returned on read, and updated with the `__unchanged__` sentinel. Changing a channel's destination while keeping a stored secret is refused (`422`, "re-enter the secret"), so an old secret cannot silently follow a new URL.
- Webhook custom headers cannot be `Authorization`, `Cookie`, `Proxy-Authorization`, `Host`, `Content-Type`, `X-CertForge-*`, or any name containing `token`, `key`, `secret` or `auth`.
- All outbound notifier and monitor requests go through one client that allows only `http` and `https` without userinfo, blocks unspecified and multicast hosts always, and blocks loopback and link-local hosts unless **Settings → Integrations → Notifications → Allow loopback and link-local** is on. Cloud metadata addresses stay blocked regardless. The check runs when you save and again when connecting, after DNS resolution, which defeats DNS rebinding. Private network ranges such as RFC 1918 are allowed. Redirects are not followed and proxy environment variables are ignored.
- DNS credential fields that hold URLs or hosts go through the same policy when saved, including a DNS lookup of the host. A later DNS change is not re-checked.
- Delivery errors are redacted against every secret value (raw and URL-escaped) before storage or logging. Email subjects and ntfy titles strip line breaks. Event payloads carry no key material, key ids or Vault addresses.
- The OIDC issuer must use `https://` unless it is a loopback host. `CF_OIDC_ALLOW_INSECURE_ISSUER=true` lifts that for development.

## Deploy target secrets
Secret fields of a deploy target are sealed, never returned (the API lists only which fields are set) and use `__unchanged__`. Changing a URL while keeping a secret is refused. Secrets for an agent-run target reach the agent inside the sealed session on either port, never separately and never in logs. Stored secrets are scrubbed (raw, URL-escaped and base64 forms) from errors, events and reports. TLS verification to a target is never disabled.

A `vault-kv` target writes into one shared Vault. Without global `delivery:write`, its path must start with `certforge/<org slug>/`. Two grants may not render the same mount and path.

## Local admin, sessions and CSRF
- The local admin is break-glass access. There is at most one. Its password (12 to 1024 characters) is stored as argon2id. Logins for a missing user take as long as a real check.
- Sessions are server-side rows. The `cf_session` cookie holds a random 256-bit token; the database stores its SHA-256. The cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` when the base URL is https, the request came over TLS, or it came from a trusted proxy with `X-Forwarded-Proto: https`. Lifetime is **Settings → Authentication → Session lifetime (hours)** (default 12 hours).
- Every session has its own CSRF token. Mutating requests must send it in `X-CSRF-Token`, except public routes. Bodies must be `application/json`, so a cross-site form cannot reach login or setup.
- A new login revokes the user's other sessions. Disabled and deleted users lose access on their next request.
- Login, OIDC start and callback, and setup are rate limited per client address (default 10 a minute, burst 5; `0` disables). Beyond the limit, login returns `429` with `Retry-After`; OIDC redirects to `/login?error=rate_limited`.

## Single sign-on
Login uses the authorization-code flow with PKCE and a nonce. Accounts match on issuer and subject, never on email. Flow state lives in an HMAC-signed `cf_oidc` cookie. Every callback failure redirects to `/login?error=<code>`. See [Access](../guide/access.md) and [ADR 0006](../internals/adr/0006-oidc-sessions.md).

## Authorization
Roles: `admin` (everything), `org-admin` (everything inside its organization except global-only actions), `operator` (certificates, credentials, accounts, clients, issue and renew), `viewer` (read only, no secrets) and `auditor` (viewer plus the audit log). Global-only actions: `settings:write`, `orgs:write`, `cas:write`, `keys:export`, `dnscreds:reveal`, `users:write`.
- A grant, or a layout in use, that hands a private key to a host needs `keys:export` on top of `clients:write`. An operator can create only certificate-only grants.
- Agents never pass these checks. They have their own principal, which every human API action refuses.
- API keys are covered in [Access](../guide/access.md#api-keys); the design is in [ADR 0007](../internals/adr/0007-rbac-bindings-and-api-keys.md).

### DNS credential secret reveal

DNS credential secrets are write-only except for a reveal call that needs `dnscreds:reveal`, is audited as `dns_credential.secret_revealed` before any value is returned, and fails closed if the audit write fails. Issue such keys sparingly.

### Server cloud identity for DNS providers

Providers that can use the server's own cloud identity (`route53`, `lightsail`, `gcloud`, `azuredns`, `azure`) need global `settings:write` to be set up that way, so one tenant cannot act as the deployment's cloud identity.

## Metrics token
`GET /metrics` is gated by a bearer token compared in constant time. A wrong token gets `401`; a disabled section gets `404`, so a prober cannot tell the two apart. See [Monitoring](monitoring.md#scrape-prometheus).

## Audit chain
`audit_events` is append-only: triggers reject updates, deletes and truncation, apart from the one re-chaining update. Each row stores the previous hash and an HMAC-SHA256 over its fields, keyed from the root secret. Verification detects an edited or removed row, and rejects an unkeyed row once the chain is keyed. A writer who also deletes the `audit.chain_keyed` setting row can still replace history wholesale with a consistent chain; keep database access tight. An audit write never fails the action it records, except where the audit trail is the point (private-key download, secret reveal). Page and actions: [Audit](../guide/audit.md). Design: [ADR 0008](../internals/adr/0008-audit-hmac-chain.md).

## Headers
Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin` and a Content-Security-Policy that allows only same-origin scripts, styles (with inline styles for the UI toolkit), images, fonts and connections, and no framing. `Strict-Transport-Security` (two years, subdomains) is sent only for requests that arrived over TLS or with `X-Forwarded-Proto: https`.

## Resource exhaustion on public routes
Body, password, hashing and timeout limits are in [Deploying](deploying.md#request-limits). Certificate import archives are also capped at 2000 entries and 128 MiB uncompressed, reject absolute paths and `..` (zip-slip) with `422`, and skip anything that is not a regular file.

## Client addresses
The client address is the TCP peer. `X-Forwarded-For` is used only when the peer is listed in **Settings → Authentication → Trusted proxies**; hops are read right to left and the first untrusted one wins, so a client cannot inject a fake address. This also applies to agent rate limits and audit entries.

## CAA pre-check
**Check CAA records** (**Settings → Issuance**) is a local convenience, not a control. The CA re-checks CAA itself when issuing (RFC 8659). Turning it off only lets a doomed order reach the CA. See [Certificates](../guide/certificates.md#caa).

## First run
Until setup completes, anyone who can reach the server can claim it. Complete setup right after the first start, keep the port private until then, or set `CF_SETUP_TOKEN` (or `CF_SETUP_TOKEN_FILE`) so setup requires it. The token is compared in constant time and failed attempts are rate limited. Setup completes once, atomically. `certforge bootstrap-admin` resets an existing local admin's password and revokes its sessions; it does not complete setup. See [Server CLI](../reference/server-cli.md).

## See also
- [Key management](key-management.md), [Deploying](deploying.md), [Troubleshooting](troubleshooting.md)
- [ADR 0020](../internals/adr/0020-agent-protocol-through-proxy.md), [Architecture](../internals/architecture.md)
