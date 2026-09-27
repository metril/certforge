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

## Issuing from the web UI

**Certificates → New certificate** opens a four-step wizard: **Names**, **Verification**, **Options**, **Review**. The summary on the right shows names, zones, verification coverage, CA, key type, and renewal as you go. Options and Review are optional: the fast path is paste names → check the pre-filled credential → **Issue certificate**. After issuing you land on the certificate's **Attempts** tab with the live attempt open. **Duplicate** on a certificate opens the same wizard pre-filled; **Edit** (`/certificates/{id}/edit`) opens it pre-filled from the existing certificate and saves with `PUT` instead — changing names shows a one-line notice that a new certificate will be issued.

### Certificate page

`/o/{org}/certificates/{id}/{tab}` — **Overview**, **Versions**, **Attempts**, **Settings**. The header shows the status, the validity bar (issued to expiry, hatched renewal window, a notch for today), the CA, ACME account, next renewal, and recent failures. Actions: **Renew now** (queues an attempt and opens **Attempts**), **Download**, **Duplicate** (opens the wizard pre-filled from this certificate), and, in the overflow menu, **Delete** (type the name to confirm — revoking a certificate is not part of Phase 1). While an attempt is running the page polls the certificate every 2 seconds, whichever tab is open; otherwise every 30 seconds, and never while the tab is hidden. A certificate waiting on a manual-dns step shows its TXT records above the tabs (see [manual-dns](#manual-dns)).

- **Overview**: names grouped by domain, the coverage list, and the effective configuration with its source (**Cert**, **Org**, **Global**, **Default**).
- **Versions**: every issued version — serial, validity (with a dashed segment marking the successor), SHA-256 fingerprint, and how it was obtained — each with its own **Download**.
- **Attempts**: see [Attempts](#attempts).
- **Settings**: the wizard's own steps (names, verification rules with coverage, options with their sources), read-only, with an **Edit** button that opens the wizard's edit route to make changes.

**Download** opens a sheet to pick a version, the format (PEM in this release), and parts: `cert`, `chain`, `fullchain`, `key`, `combined`. One part downloads a `.pem` file; more than one downloads a `.zip`. The `key` and `combined` chips need the `keys:export` permission (global admins by default) and are disabled with an explanation otherwise; every key download is written to the audit log before any byte is sent.

## Names

A certificate has a common name plus any number of SANs: wildcards (`*.example.com`, leftmost label only), names from different zones, and IP addresses where the CA supports them (not with DNS-01). Names are lower-cased and de-duplicated; the first is the common name. Changing names issues a new certificate immediately; other changes apply at the next renewal.

In the web UI, paste names into the wizard's multi-line box separated by commas, spaces, semicolons, or new lines; each becomes a chip, grouped by registered domain (for example `a.example.co.uk` groups under `example.co.uk`; a private zone like `lab.local` groups under itself).

- `*.example.com` is a wildcard and is marked **DNS only**: wildcards can only be proven with DNS verification (dns-01 or manual-dns), never HTTP-01. A wildcard under a registrable "private" zone such as `*.github.io` groups and validates the same way; a wildcard directly on an ICANN suffix such as `*.co.uk` is invalid, since nobody controls that whole zone.
- IP addresses are marked **IP**. Phase 1 cannot validate IP names (dns-01 and manual-dns only), so the certificate will fail until HTTP-01 lands.
- Invalid names get a red outline; hover the icon for the reason. Remove them to continue.
- The first valid name is the common name. Drag another chip onto the Common name box, or use its crown button, to change it.
- A certificate holds at most 100 names.

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

### The verification rules step (web UI)

Pick a **Method** first: **DNS-01** (a DNS credential writes the TXT record) or **Manual DNS** (you add the records by hand; see [manual-dns](#manual-dns)). One method per certificate in this version; a per-rule method selector arrives in Phase 4.

Rules are an ordered list; drag a row's grip to reorder, or use its **Move up**/**Move down** buttons. The wizard pre-fills one rule per registered domain with the credential you last used for that zone (remembered locally) or, failing that, a credential an existing certificate already uses there. If no credential is known and your organization's catch-all rule already covers the name, no rule is added; otherwise the rule is added without a credential, and the **Coverage** list shows **No credential** — issuing stays blocked until you pick one or use **Add credential**, which opens the provider picker and the credential form without leaving the wizard. **Advanced** per rule: propagation wait, resolvers, and a CNAME alias zone.

The **Coverage** panel lists every certificate name with the rule that proves it, or **Catch-all: inherited from Org/Global** when none of the certificate's own rules match but the org or global catch-all does. A name with neither is flagged and blocks **Next**.

### CNAME delegation

To keep DNS API credentials away from a production zone, point `_acme-challenge.<name>` at a record in a separate zone with a CNAME, for example `_acme-challenge.www.example.com CNAME www.example.com.acme.example.net`. lego follows the CNAME automatically. Set **CNAME alias zone** to `acme.example.net` and give the rule a credential for that zone.

### Options

Every issuance default (CA, account, key type, renewal, preferred chain, reuse key, Must-Staple, propagation wait, resolvers) is shown with its effective value and source badge. Turn on **Override** to set it for this certificate only; **Reset to inherited** removes the override. See [issuance defaults](configuration.md#issuance-defaults).

### Review

Name the certificate (defaults to the common name), check the coverage list and the effective options with their source (**Cert**, **Org**, **Global**, **Default**), then **Issue certificate**.

### DNS credentials

Issuers → DNS credentials. The form comes from the provider schema ([DNS providers](dns-providers.md)). Secret fields are stored encrypted and never returned; the API lists them in `storedSecrets`. On update, send `__unchanged__` to keep a secret. **Test** creates and deletes a TXT record at `_acme-challenge._certforge-test.<zone>`. A credential used by any rule cannot be deleted.

### manual-dns

When an attempt reaches a manual rule, the certificate shows the TXT records to add (`GET .../manual-dns`: name, type, value, TTL, expiry). Add them, wait for them to resolve, then press **I've added them** (`POST .../manual-dns/confirm`). The attempt then checks propagation and continues.

If nobody confirms within 1 hour, the attempt fails with `manual-dns: TXT records were not confirmed in time`, the pending records are dropped, and the normal backoff schedules the next attempt, which shows fresh records. Remove old TXT records by hand.

In the web UI, a pending certificate with records waiting shows an amber **Manual DNS** card on its own page and at the top of the Overview queue. It lists each record (name, type, value, TTL) with a copy button per field and **Copy all as zone lines** for pasting straight into a zone file. Add the records at your DNS host, then select **I've added them**; the card shows the CA's answer inline if nothing was waiting or the records expired, and the **Attempts** tab shows progress.

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

The certificate's **Attempts** tab shows every attempt, newest first, as a step timeline. The failing step (if any) opens by default with its message; the raw log is collapsed behind **Raw log**, which adds a search box and a copy button once opened. While an attempt is `running` the tab polls every 2 seconds; once none is, it slows to 30 seconds, and never polls while the tab is hidden.

### Troubleshooting

A failed attempt shows a one-line explanation of the ACME error plus a link to the fix:

| ACME error | Meaning | What to do |
|---|---|---|
| `rateLimited` | The CA's rate limit was reached | Wait for the retry time shown; avoid re-issuing identical names |
| `dns`, `incorrectResponse` | The TXT record was missing or wrong when the CA looked | Check the record, CNAME delegation, and the propagation wait |
| `unauthorized` | The CA rejected the proof | Check the verification rule that covers the name |
| `caa` | A CAA record forbids this CA | Add the CA's identifier to the domain's CAA record |
| `externalAccountRequired` | The CA needs EAB | Add the key ID and HMAC on the CA |
| `badNonce`, `serverInternal`, `orderNotReady` | Transient | CertForge retries with backoff (5 minutes doubling to 24 hours) |

Any other ACME error type shows as "The CA returned `<type>`."; open **Raw log** for the underlying detail.

## Downloads

`GET .../versions/{vid}/download?format=pem&parts=...`. Parts: `cert`, `chain`, `fullchain`, `key`, `combined` (fullchain + key). One part returns a PEM file; several return a zip (`privkey.pem` and `combined.pem` with mode 0600). `key` and `combined` need the `keys:export` permission (global admin only) and every such download is written to the audit log before any byte is sent.

### Formats

Four output formats:

- `pem`: `cert`, `chain`, `fullchain`, `combined` (fullchain + key), `key`, and `extra` (the leaf and chain of each layout's extra certificates, concatenated in order). One part returns a PEM file; several return a zip.
- `der`: `cert` → `cert.der`; `chain` → one `chain-N.der` file per chain certificate; `key` → `privkey.der` (PKCS#8). `fullchain` and `combined` are not available as DER, since a DER file holds exactly one PEM block.
- `p12`: one password-protected `<name>.p12` holding the leaf, its chain, any extra certificates (as CA certificates), and the key.
- `jks`: one password-protected `<name>.jks` Java keystore holding a private-key entry (leaf, key, chain) and one trusted-certificate entry per extra certificate; the store password equals the key password and must be at least 6 characters.

`key`, `combined`, and every p12/jks export need the `keys:export` permission (global admin only) and are written to the audit log before any byte is sent. DER, PKCS#12 and JKS downloads and exports land in a later Phase 4A task.
