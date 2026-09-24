# Certificates

How CertForge obtains certificates: CAs, ACME accounts, verification, defaults, renewal and downloads.

## Certificate authorities

Issuers → CAs. Pick a preset or Custom.

| Preset | Directory | EAB |
|---|---|---|
| `letsencrypt` | `https://acme-v02.api.letsencrypt.org/directory` | no |
| `letsencrypt-staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` | no |
| `zerossl` | `https://acme.zerossl.com/v2/DV90` | required |
| `buypass` | `https://api.buypass.com/acme/directory` | no |
| `google` | `https://dv.acme-v02.api.pki.goog/directory` | required |
| `sslcom` | `https://acme.ssl.com/sslcom-dv-rsa` | required |
| `custom` | any `https://` directory URL | optional |

- **Trust bundle**: PEM roots added to the system pool when talking to a private ACME server (Pebble, step-ca, Vault ACME).
- **Resolvers**: `host` or `host:port` DNS servers used for propagation checks when neither the rule nor the defaults name any.
- Only a global admin (`cas:write`) adds or edits CAs. In Phase 1 a CA row belongs to one org; shared global CAs arrive in Phase 2.
- A CA cannot be deleted while accounts, certificates or defaults reference it.

### External Account Binding (EAB)

ZeroSSL, Google Trust Services and SSL.com require EAB. Create the key id and HMAC in the CA's console, then enter them on the CA. The HMAC is write-only: the API reports `hasEab` and never returns it. On update, leave it empty or send `__unchanged__` to keep it; send an empty string to remove it.

## ACME accounts

Issuers → ACME accounts → Register. CertForge generates a P-256 account key, registers it at the CA (with the CA's EAB), and stores the key envelope-encrypted. The registration URI is the account's `kid`. Deleting an account removes it from CertForge only; it is not deactivated at the CA. Accounts referenced by certificates or defaults cannot be deleted.

## Defaults and overrides

Every issuance field exists at three levels: global (Settings → Issuance defaults), org, and certificate. A null value inherits from the level above; unset globals fall back to built-in values.

| Field | Built-in | Notes |
|---|---|---|
| `caId`, `accountId` | none | Issuance fails with a clear error until both are set somewhere. The account must belong to the CA. |
| `keyType` | `ec256` | `rsa2048`, `rsa3072`, `rsa4096`, `ec256`, `ec384`. |
| `renewPolicy` | `percent`, 33 | See [Renewal](#renewal). |
| `preferredChain` | empty | Issuer common name of an alternate chain. |
| `reuseKey` | off | Keeps the private key across renewals when the key type is unchanged. |
| `mustStaple` | off | Adds the OCSP must-staple extension. |
| `verificationRules` | none | Catch-all rules appended after a certificate's own rules. A level that sets this replaces the level above's list entirely — global, org and certificate never merge, only the closest non-null one applies. |
| `propagationSeconds` | none (provider default) | How long to wait for TXT records. Unset (or 0) uses each rule's own DNS provider's default instead, so a DNS credential's own `*_PROPAGATION_TIMEOUT` setting takes effect; set a value here or on a rule to override it. |
| `resolvers` | none | Resolvers for propagation checks. |

`GET /api/v1/orgs/{orgId}/issuance-defaults/effective` and each certificate's `effective` field show the resolved value and its `source`: `default` (built-in), `global`, `org` or `cert`. A changed default applies at the next renewal of every certificate that inherits it. Saving the global section (`PUT /settings/issuance_defaults`) and org defaults (`PUT /orgs/{orgId}/issuance-defaults`) both validate that a referenced CA, account or DNS credential exists (and, for org defaults, belongs to the org) before storing; an unknown id is a 422.

## Names

A certificate has a common name plus any number of SANs: wildcards (`*.example.com`, leftmost label only), names from different zones, and IP addresses where the CA supports them (not with DNS-01). Names are lower-cased and de-duplicated; the first is the common name. Changing names issues a new certificate immediately; other changes apply at the next renewal.

## Verification rules

Each certificate carries an ordered list of rules. For every name the first matching rule wins; the inherited catch-all rules (certificate overrides, then org, then global) come after the certificate's own rules.

| `match` | Matches | Does not match |
|---|---|---|
| `*` | every name | |
| `*.example.com` | `a.example.com`, `*.example.com` | `example.com`, `b.a.example.com` |
| `example.com` | `example.com`, `a.example.com`, `b.a.example.com`, `*.example.com` | `badexample.com` |

To give one name its own credential, put a rule for exactly that name first: `a.example.com` above `example.com`.

| `method` | Needs | Who acts |
|---|---|---|
| `dns-01` | `dnsCredentialId` | CertForge, via the lego provider of that credential |
| `manual-dns` | nothing | an operator adds TXT records and confirms |

Optional per rule: `propagationSeconds`, `resolvers`, `cnameAliasZone`.

- **Propagation budget**: each name gets its own propagation-check budget (its rule's `propagationSeconds`, or its provider's default) once past any manual-dns wait; it fails within that budget regardless of how long another name of the same certificate is still allowed to run (for example a `manual-dns` name's hour-long wait does not extend a `dns-01` name's much shorter budget).
- **Ordering with overlapping zones**: put the narrow rule first. With `dev.example.com → B` above `example.com → A`, `x.dev.example.com` uses B; reversed, A shadows B.
- **Uncovered names**: if a name matches no rule and no catch-all exists, the attempt fails before contacting the CA: `no verification rule matches <name> and no catch-all rule is configured`. Add a rule or a catch-all in the defaults.
- **Apex and wildcard** (`example.com` + `*.example.com`) share `_acme-challenge.example.com`; the rule matching the apex serves both.
- **CNAME delegation**: point `_acme-challenge.<name>` at a record in a zone your credential controls. lego follows the CNAME automatically. Set `cnameAliasZone` to that zone; a mismatched or missing CNAME fails that name with a clear message on its first propagation check, within its own per-name propagation budget — not necessarily "early", and independent of how long any other name of the same certificate is still allowed to wait.
- Phase 1 supports DNS methods only; HTTP-01 and TLS-ALPN-01 arrive in Phase 4.

### DNS credentials

Issuers → DNS credentials. The form comes from the provider schema ([DNS providers](dns-providers.md)). Secret fields are stored encrypted and never returned; the API lists them in `storedSecrets`. On update, send `__unchanged__` to keep a secret. **Test** creates and deletes a TXT record at `_acme-challenge._certforge-test.<zone>`. A credential used by any rule cannot be deleted.

### manual-dns

When an attempt reaches a manual rule, the certificate shows the TXT records to add (`GET .../manual-dns`: name, type, value, TTL, expiry). Add them, wait for them to resolve, then press **I've added them** (`POST .../manual-dns/confirm`). The attempt then checks propagation and continues.

If nobody confirms within 1 hour, the attempt fails with `manual-dns: TXT records were not confirmed in time`, the pending records are dropped, and the normal backoff schedules the next attempt, which shows fresh records. Remove old TXT records by hand.

## Renewal

- `percent` N: renew when N% of the lifetime remains (default 33: day 60 of a 90-day certificate, day 4 of a 6-day certificate).
- `days` N: renew N days before expiry.
- Renewal is never scheduled earlier than half the lifetime, so a 30-day policy on a 6-day certificate cannot loop.
- `useAri` is stored; ACME Renewal Information arrives in Phase 4.
- The scheduler checks every 5 minutes. **Renew now** enqueues immediately; it reports `enqueued: false` if an attempt is already queued or running.

### Failures and backoff

A failed attempt sets `failureCount`, `lastError`, and the next try to `min(5 min · 2^(failures−1), 24 h)` ±20%. When the CA answers `rateLimited` with `Retry-After`, the next try is no earlier than that. A failed renewal leaves a still-valid certificate `active`. CAA checks and the rate-limit ledger appear as `skipped` steps until Phase 4.

## Attempts

Each attempt records a step timeline: `caa`, `rate_ledger`, `account`, `order`, `challenge <name>`, `finalize`, `store`, each `running`, `success`, `failed`, `skipped` or `waiting_manual`, plus a log, the ACME error type (for example `urn:ietf:params:acme:error:rateLimited`) and `retryAfter`.

## Downloads

`GET .../versions/{vid}/download?format=pem&parts=...`. Parts: `cert`, `chain`, `fullchain`, `key`, `combined` (fullchain + key). One part returns a PEM file; several return a zip (`privkey.pem` and `combined.pem` with mode 0600). `key` and `combined` need the `keys:export` permission (global admin only) and every such download is written to the audit log before any byte is sent. DER, PKCS#12 and JKS arrive in Phase 4.
