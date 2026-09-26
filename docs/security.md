# Security

## KEK handling

- The key-encryption key (KEK) comes from `CF_KEK` (base64) or `CF_KEK_FILE`. It is never stored in the database or logged, and config errors never echo it.
- Each secret is sealed with its own AES-256-GCM data key. The data key is wrapped by the KEK. The KEK id (`static-` plus 16 hex characters of `SHA-256("certforge-kek-id:" || key)`, a domain-separated hash, not a plain hash of the key) is stored in every blob and bound as authenticated data.
- At startup the server decrypts the `crypto.canary` setting, or writes it on first boot. With a wrong KEK the server keeps serving, but `/readyz` returns 503 with `kek: failed` and every secret read fails with a clear error. Nothing is overwritten.
- Escrow the KEK outside the server. Without it, backups cannot be decrypted.

## Local admin, sessions, and CSRF

- The local admin is break-glass access. There is at most one, enforced by a partial unique index. Its password (12 to 1024 characters) is stored as argon2id (64 MiB, t=3, p=2, 16-byte salt). Logins for a missing user spend the same time as a real check.
- Sessions are server-side rows. The `cf_session` cookie holds a random 256-bit token. The database stores only its SHA-256. The cookie is `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` when the base URL is https, the request came over TLS, or the request came from a trusted proxy (Settings → Authentication → Trusted proxies) with `X-Forwarded-Proto: https`. Lifetime is Settings → Authentication → Session lifetime (default 12 hours). Expired sessions are rejected and purged hourly.
- Every session has its own CSRF token, returned by `GET /api/v1/auth/me`. POST, PUT, PATCH, and DELETE with a session must send the session's CSRF token in X-CSRF-Token, except on public routes (login, setup), which accept a stale session cookie without it. Request bodies must be `application/json` (415 otherwise), so a cross-site form cannot reach even public endpoints such as login and setup.
- A new login (password or OIDC) revokes the user's other sessions (audited as session.revoked).
- Password logins and the OIDC callback are limited per client address (Settings → Authentication → Login rate limit, defaults 10 a minute with burst 5; 0 disables it), IPv6 grouped by /64, in memory; beyond that the local login API returns 429 with Retry-After, while the OIDC callback (a browser navigation) instead redirects to /login?error=rate_limited.
- Disabled users and deleted users lose access on their next request.
- Site scope is not modelled yet: role bindings with a non-NULL `site_id` are ignored when a principal is loaded.

## Single sign-on

Login is auth code with PKCE and a nonce; accounts are matched by (issuer, subject) only, never by email, and `email_verified` is never consulted. Flow state (state, nonce, PKCE verifier, return path) rides in the `cf_oidc` cookie, HMAC-SHA256 signed with a key derived from the KEK (`HKDF(KEK, "certforge-oidc-state")`), not in server-side storage. Every callback failure — rate limited, disabled, denied, or any other error — redirects the browser to `/login?error=<code>`, never problem+json. See [ADR 0006](adr/0006-oidc-sessions.md).

## API keys

A key can do at most what its creator can do right now, restricted to its scopes and to its org when it has one; it stops working when revoked, expired, or when its creator is disabled. Keys cannot create keys. The API-key path is taken only for `Authorization: Bearer cf_<prefix>_<secret>` — any other scheme or bearer content (a reverse proxy's `Basic` header, an upstream JWT) is ignored and the request falls through to its cookie session, if any; when a request carries both a valid bearer and a cookie, the bearer decides the outcome and needs no CSRF header.

## Authorization

Roles: `admin` (everything, including CAs, KEK, global settings, key export), `org-admin` (everything within its org except global-only actions), `operator` (certificates, credentials, accounts, clients, issue and renew), `viewer` (read-only, no secrets), `auditor` (viewer plus audit log). Global-only actions: settings:write, orgs:write, cas:write, keys:export, users:write. users:read is readable by any role that holds it in some org (org-admins pick users for bindings). Agents never pass `Can()`; they use their own mTLS listener. Phase 1 seeds only the global `admin` binding for the local admin. See [ADR 0007](adr/0007-rbac-bindings-and-api-keys.md) for how role bindings and API keys fit together.

Phase 3 adds `delivery:read` (viewer and up) and `delivery:write` (operator and up) for layouts, deploy targets and hooks; clients, grants, deployments and hook runs use `clients:read`/`clients:write`. So an API key with `clients:write` can create, change, redeploy and delete grants (choosing among existing layouts, targets and hooks), while one with `delivery:write` can change layouts, deploy targets and hooks, which re-renders every grant using them. API key scopes gain `clients:read`, `delivery:read` and `delivery:write`. Agents authenticate only on the agent listener with their client certificate; their principal (`kind = agent`) is refused by every human API action.

OIDC group bindings (subject_type oidc_group) match the groups recorded at the user's last login.

## Audit log

`audit_events` is append-only. Triggers reject UPDATE, DELETE, and TRUNCATE, except the single three-column update `audit.Rechain` performs (`hash`, `prev_hash`, `hash_alg`; migration 00006). Each row stores `prev_hash` (unique) and `hash = HMAC-SHA256(key, hash_alg, prev_hash, timestamp, actor, action, resource, org, ip, canonical details)` — the `hash_alg` label itself is folded into the MAC input, so it cannot be swapped on a row without invalidating its hash — with the key derived from the KEK (ADR 0008). Appends are serialized with a Postgres advisory lock. Logins, failed logins, logouts, `session.revoked`, setup, settings changes, `user.update`, org, site, and role-binding create/update/delete, `api_key.create`/`api_key.revoke`, and `audit.export` are recorded.

`Auditor.Verify` walks the chain and detects an in-place edit to any row, or a row deleted from the middle of the chain: either breaks the `prev_hash`/`hash` link and `Verify` reports the first bad id. Two independent downgrade gates reject a `sha256` row once the chain is known to be keyed (ADR 0008): a monotonic rule (once a `hmac-sha256` row has been seen, any later `sha256` row is broken outright regardless of its own internal consistency), and the `audit.chain_keyed` setting flag, read back up front — the second gate catches an adversary who bypasses the trigger and replaces the *whole* table with a self-consistent legacy-only chain, which the monotonic rule alone cannot see. Appending or altering rows needs the KEK; an attacker with table-owner access who also deletes the `audit.chain_keyed` setting row can still replace history wholesale with a chain that passes clean — only external head-hash anchoring (a known gap, below) closes that residual. `Verify` does not detect truncation from the tail (deleting the newest rows leaves a shorter but internally consistent chain), and the application role still owns `audit_events`. Hardening follow-ups: anchoring the head hash outside the table (e.g. in a separate append-only store or external log), and running the application under a role that cannot alter or own `audit_events`.

**Audit-write failure policy:** an audit write never fails the action it is recording. `setup.Complete` and `SetAdminPassword` (bootstrap-admin) commit their transaction first; if the follow-up `Auditor.Record` call then fails, the error is logged and the action still reports success, since undoing an already-committed setup or password reset would be worse than a missing audit row. The same log-and-continue pattern is used wherever audit recording follows a request that already succeeded (see `Server.audit` in `internal/api`).

**Readers:** global auditors and admins see every event; org auditors and org-admins see their orgs' events, never global ones. `GET /audit/verify` needs global `audit:read`: the chain it walks covers every org and every global event, so an org-scoped auditor cannot call it even for their own org. `GET /audit/export` neutralizes formula-like cells (a leading `=`, `+`, `-`, `@`, tab, or CR gets a leading apostrophe) so a malicious display name or details value cannot execute as a spreadsheet formula when the export is opened.

## Agent identity

Agents authenticate with mutual TLS to a separate listener, not with sessions or API keys: CertForge runs its own ECDSA P-256 agent CA (`agent_cas`, key envelope-encrypted like certificate keys) that issues each agent a `clientAuth` certificate carrying only the URI SAN `urn:certforge:client:<uuid>`, and signs the listener's own `serverAuth` certificate. Several CAs stay trusted at once so rotating the signing CA never strands an already-enrolled agent, and retiring a CA is blocked while any live agent certificate still depends on it. See ADR 0009 for the full design, including why no separate application-layer handshake is layered on top of mTLS.

## Headers

Every response, API and web UI alike, carries (`internal/api/router.go`'s `securityHeaders`):

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: same-origin`
- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'`. `script-src 'self'` holds because the SPA has no inline scripts — the pre-paint theme script is the external `/theme-init.js` — and the vendored Swagger UI at `/api/docs` loads only its own same-origin bundle, fetching `/api/v1/openapi.json` (`validatorUrl: null`, so no third-party call). `style-src` allows `'unsafe-inline'` for Radix's inline style attributes and Swagger UI's injected `<style>` tags.
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`, only on a request that arrived over TLS or with `X-Forwarded-Proto: https` (a plain-HTTP deployment, or one behind a proxy that doesn't set that header, never gets an HSTS header telling browsers to require HTTPS).

## Resource exhaustion on public routes

- Request bodies on `POST`/`PUT`/`PATCH` under `/api/v1` are capped at 1 MiB (`http.MaxBytesReader`); an oversized body gets `413 Payload too large` as `problem+json` before it reaches a handler.
- Passwords are capped at 1024 bytes in `POST /api/v1/auth/login` and `POST /api/v1/setup/complete` (`422` before any hashing), and `authn.HashPassword`/`VerifyPassword` enforce the same limit for any other caller.
- argon2 hashing/verification is limited to 4 concurrent operations server-wide (`internal/authn`'s package-level semaphore); a login or setup-complete that arrives while all slots are held gets `503 Service busy` with `Retry-After: 1` instead of queuing behind unbounded argon2 work.
- The HTTP server sets `ReadHeaderTimeout` (10s), `ReadTimeout` (30s), and `IdleTimeout` (120s), so a slow or idle client cannot hold a connection open indefinitely.

## Client addresses

The client address comes from the TCP peer. X-Forwarded-For is used only when the peer is in Settings → Authentication → Trusted proxies; hops are read right to left and the first untrusted one wins, so a client cannot inject a fake address.

## First run

Until setup completes, anyone who can reach the server can claim it through `POST /api/v1/setup/complete`. Complete setup right after the first start, or keep the port private until then. Completion is atomic (transaction plus advisory lock) and happens only once.

`bootstrap-admin` only resets an existing local admin's password (clearing its disabled flag) and revokes that user's sessions; it refuses while setup is pending, since no local admin exists yet outside the setup wizard. It does not complete setup, so `POST /api/v1/setup/complete` stays available, and reachable by anyone, until setup is actually run.

## Agent listener and enrolment

`POST /agent/v1/enroll` is rate limited per client address the same way login is (its own `EnrollLimiter`, not shared with login's), so brute-forcing a token cannot be sped up by parallelizing. Enrolment tokens are single-use (`used_at` set atomically on first consumption; a replayed or concurrently raced token loses), stored only as a SHA-256 hash, and pin the agent CA fingerprint that signed the listener certificate at issuance time, so a token minted before a CA rotation cannot be replayed against a different CA later. The server refuses every agent certificate except the newest serial issued to its client: re-enrolling or renewing immediately invalidates whatever certificate the agent held before. This is checked on every REST request (`requireAgent`) and, for an already-open WebSocket, on every message (`agents.OnMessage` re-runs the same `Authenticate` check, not only once at connect) — so revocation is immediate and needs no CRL or OCSP responder: a revoked client's serial no longer matches, and its certificate stops authenticating on its very next request or socket message, whichever comes first.

## Agent hooks and writes

A compromised server could push any argv, or any file path, to every agent. Both are therefore off by default and allowlisted locally, by the agent operator, not the server: hooks run only if `argv[0]` matches an entry in `CF_HOOK_ALLOW` exactly (argv is never run through a shell, and each run is recorded — `hook.run` audit event, hook run history); files are only written or removed under a directory listed in `CF_WRITE_ALLOW` (checked after resolving symlinks on the deepest existing parent, so a symlink cannot be used to escape an allowed directory). With either variable empty, the corresponding action always fails cleanly instead of running unconstrained. Allow narrow, purpose-built executables (never a shell or interpreter) and only the directories the agent actually needs to write.
