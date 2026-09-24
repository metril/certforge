# Security

## KEK handling

- The key-encryption key (KEK) comes from `CF_KEK` (base64) or `CF_KEK_FILE`. It is never stored in the database or logged, and config errors never echo it.
- Each secret is sealed with its own AES-256-GCM data key. The data key is wrapped by the KEK. The KEK id (`static-` plus 16 hex characters of a SHA-256 of the key) is stored in every blob and bound as authenticated data.
- At startup the server decrypts the `crypto.canary` setting, or writes it on first boot. With a wrong KEK the server keeps serving, but `/readyz` returns 503 with `kek: failed` and every secret read fails with a clear error. Nothing is overwritten.
- Escrow the KEK outside the server. Without it, backups cannot be decrypted.

## Local admin, sessions, and CSRF

- The local admin is break-glass access. There is at most one, enforced by a partial unique index. Its password (at least 12 characters) is stored as argon2id (64 MiB, t=3, p=2, 16-byte salt). Logins for a missing user spend the same time as a real check.
- Sessions are server-side rows. The `cf_session` cookie holds a random 256-bit token. The database stores only its SHA-256. The cookie is `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` when the base URL is https or the request came over TLS. Lifetime is 12 hours. Expired sessions are rejected and purged hourly.
- Every session has its own CSRF token, returned by `GET /api/v1/auth/me`. POST, PUT, PATCH, and DELETE with a session must send it in `X-CSRF-Token`, or they get 403. Request bodies must be `application/json` (415 otherwise), so a cross-site form cannot reach even public endpoints such as login and setup.
- Disabled users and deleted users lose access on their next request.
- Site scope is not modelled in Phase 1: role bindings with a non-NULL `site_id` are ignored when a principal is loaded, until site scope lands in Phase 2.
