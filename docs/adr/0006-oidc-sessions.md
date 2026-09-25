# 0006: OIDC login and server-side sessions

Status: accepted (Phase 2)

## Context
Humans sign in through the organisation's identity provider; the local admin stays as break-glass. The server already keeps sessions in Postgres with a CSRF token per session.

## Decision
- Auth code with PKCE (S256) and a nonce, via coreos/go-oidc and x/oauth2. Discovery is cached per issuer for 10 minutes and dropped when Settings → Authentication is saved.
- State, nonce, PKCE verifier and the return path travel in `cf_oidc`, an HttpOnly, SameSite=Lax cookie scoped to `/api/v1/auth/oidc`, valid 10 minutes and HMAC-SHA256 signed with `HKDF(KEK, "certforge-oidc-state")`. No server-side flow table.
- Users are keyed by (issuer, subject); email, display name and groups are refreshed at every login. `email_verified` is not consulted: an account is never linked by email, only by (issuer, subject), so a provider that never verifies email cannot be used to hijack an existing local account. Group role bindings match the groups from the last login. No refresh tokens are kept: a CertForge session lives for Session lifetime regardless of the IdP session.
- Every login revokes the user's other sessions; disabling a user revokes all of them.
- The login rate limit (10/min, burst 5 per client address) is an in-memory token bucket, applied to the OIDC callback as well as local login. A rate-limited or otherwise failed callback is always a 302 to `/login?error=<code>` (never problem+json), since the callback is a browser navigation, not an API call.
- CertForge runs as a single replica in v1 (docs/design.md, Risks); a second replica would need the limiter in Postgres.

## Consequences
Removing someone from a group at the IdP takes effect at their next login. The state cookie needs no storage but is only as secret as the KEK.
