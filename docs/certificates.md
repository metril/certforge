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

`/o/{org}/certificates/{id}/{tab}` — **Overview**, **Versions**, **Attempts**, **Settings**. The header shows the status, the validity bar (issued to expiry, hatched renewal window, a notch for today, and the CA's ARI window as a bracket above it when one exists — see [ARI](#ari)), the CA, ACME account, next renewal, and recent failures; an unmanaged certificate shows a **Managed externally** chip beside the status, alongside these same fields rendered as "–" for CA and Account and "Not renewed here" for next renewal, not in their place (see [Unmanaged certificates](#unmanaged-certificates)). Actions: **Renew now** (queues an attempt and opens **Attempts**), **Download**, **Duplicate** (opens the wizard pre-filled from this certificate), and, in the overflow menu, **Delete** (type the name to confirm — revoking a certificate is not part of Phase 1). While an attempt is running the page polls the certificate every 2 seconds, whichever tab is open; otherwise every 30 seconds, and never while the tab is hidden. A certificate waiting on a manual-dns step shows its TXT records above the tabs (see [manual-dns](#manual-dns)). The full screen, including the unmanaged chip and Upload new version, is described in [web-ui.md#certificate-detail](web-ui.md#certificate-detail); its **Deployments** tab is in [web-ui.md#certificate-deployments](web-ui.md#certificate-deployments).

- **Overview**: names grouped by domain, the coverage list, and the effective configuration with its source (**Cert**, **Org**, **Global**, **Default**).
- **Versions**: every issued version — serial, validity (with a dashed segment marking the successor), SHA-256 fingerprint, how it was obtained, and a **No key** chip for a keyless version — each with its own **Download**.
- **Attempts**: see [Attempts](#attempts); the `caa` and `rate_ledger` steps are covered in [CAA](#caa) and [Rate limits](#rate-limits).
- **Settings**: the wizard's own steps (names, verification rules with coverage, options with their sources), read-only, with an **Edit** button that opens the wizard's edit route to make changes (disabled on an unmanaged certificate).

**Download** opens a sheet to pick a version, a format (PEM, DER, PKCS#12 or JKS) and, below it, that format's parts or password — see [Downloads](#downloads) and [Formats](#formats) for what each one contains and [web-ui.md#certificate-detail](web-ui.md#certificate-detail) for the sheet itself.

## Names

A certificate has a common name plus any number of SANs: wildcards (`*.example.com`, leftmost label only), names from different zones, and IP addresses where the CA supports them (not with DNS-01). Names are lower-cased and de-duplicated; the first is the common name. Changing names issues a new certificate immediately; other changes apply at the next renewal.

In the web UI, paste names into the wizard's multi-line box separated by commas, spaces, semicolons, or new lines; each becomes a chip, grouped by registered domain (for example `a.example.co.uk` groups under `example.co.uk`; a private zone like `lab.local` groups under itself).

- `*.example.com` is a wildcard and is marked **DNS only**: wildcards can only be proven with DNS verification (dns-01 or manual-dns), never HTTP-01. A wildcard under a registrable "private" zone such as `*.github.io` groups and validates the same way; a wildcard directly on an ICANN suffix such as `*.co.uk` is invalid, since nobody controls that whole zone.
- IP addresses are marked **IP**. CertForge cannot validate an IP name with any of its methods yet, so the certificate will fail.
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

### Verification methods

| `method` | Needs | Who acts |
|---|---|---|
| `dns-01` | `dnsCredentialId` | CertForge, via the lego provider of that credential |
| `manual-dns` | nothing | an operator adds TXT records and confirms |
| `http-01` | `via` (`server`, the default, or `agent`); `clientId` and, optionally, `webroot` when `via: agent` | `via: server`: CertForge itself — see [http-01](#http-01). `via: agent`: the named client, over its agent connection (Phase 4A Task 7/8). |
| `tls-alpn-01` | `clientId` | the named client, on its own TLS listener (Phase 4A Task 7/8); there is no server mode |

Optional per `dns-01`/`manual-dns` rule: `propagationSeconds`, `resolvers`, `cnameAliasZone`. `http-01` and `tls-alpn-01` rules take none of those (they have no TXT propagation to wait on).

- **Propagation budget**: each name gets its own propagation-check budget (its rule's `propagationSeconds`, or its provider's default) once past any manual-dns wait; it fails within that budget regardless of how long another name of the same certificate is still allowed to run (for example a `manual-dns` name's hour-long wait does not extend a `dns-01` name's much shorter budget).
- **Ordering with overlapping zones**: put the narrow rule first. With `dev.example.com → B` above `example.com → A`, `x.dev.example.com` uses B; reversed, A shadows B.
- **Uncovered names**: if a name matches no rule and no catch-all exists, the attempt fails before contacting the CA: `no verification rule matches <name> and no catch-all rule is configured`. Add a rule or a catch-all in the defaults.
- **Apex and wildcard** (`example.com` + `*.example.com`) share `_acme-challenge.example.com` under dns-01/manual-dns; the rule matching the apex serves both. A wildcard name can only ever be proven with dns-01 or manual-dns — no ACME CA offers http-01 or tls-alpn-01 for a wildcard authorization — so **a wildcard name skips any rule whose method is http-01 or tls-alpn-01 and matches the next rule in order instead**, exactly as if that rule did not match it at all. This means a zone rule that also happens to cover a wildcard (`example.com` matches `*.example.com` too) can use http-01 for the zone's ordinary names while a more specific `*.example.com` rule further down the list still gets the wildcard onto dns-01. It is only an error — a 422 on `verificationRules` at create/update time, or "no verification rule matches" once the attempt's router is built — when a wildcard name is left with no rule left to match after every http-01/tls-alpn-01 rule in its path has been skipped this way.
- **CNAME delegation**: point `_acme-challenge.<name>` at a record in a zone your credential controls. lego follows the CNAME automatically. Set `cnameAliasZone` to that zone; a mismatched or missing CNAME fails that name with a clear message on its first propagation check, within its own per-name propagation budget — not necessarily "early", and independent of how long any other name of the same certificate is still allowed to wait.
- A certificate's rules can mix dns-01, http-01 and tls-alpn-01 across its names — see [Mixing methods](#mixing-methods).

#### http-01

With `via: server` (the default), CertForge answers the ACME CA's http-01 validation request itself: it stores the token's key authorization in memory for up to 10 minutes and serves it at `GET /.well-known/acme-challenge/{token}` on the main HTTP listener — unauthenticated, plain text, not under `/api/v1` (see [docs/api.md](api.md)). The CA must be able to reach that path over plain HTTP on port 80 for the certificate's names, so put CertForge's main listener behind (or route port 80 directly to) whatever serves those names; see [docs/operations.md](operations.md) for a reverse-proxy example.

With `via: agent`, the named client answers instead: on its own http-01 listener (`CF_AGENT_HTTP01_LISTEN`) when it has one, or by writing the token to a file under `webroot` for another web server on that host to serve — set `webroot` only when the client has no listener of its own. See [agent.md#challenge-serving](agent.md#challenge-serving).

#### TLS-ALPN-01

`tls-alpn-01` has no server mode: the named client answers on its own TLS listener (`CF_AGENT_TLSALPN_LISTEN`), presenting a self-signed certificate with the validation value in a `acmeIdentifier` extension during the TLS handshake on port 443 — there is no file to write and no `webroot`. See [agent.md#challenge-serving](agent.md#challenge-serving).

#### Mixing methods

A certificate's rules no longer have to share one method: `www.example.com` can use `dns-01` while `api.example.com` uses `http-01` and `mail.example.com` uses `tls-alpn-01`, all in the same certificate and the same CA order. Each name's own rule decides its method exactly as in [Verification rules](#verification-rules) — there is nothing extra to configure to mix them.

Internally, a certificate whose names resolve to more than one challenge type is issued through a CertForge-driven order (see [ADR 0012](adr/0012-mixed-method-order-flow.md)) instead of handing the whole order to lego: every `dns-01` name's TXT record is presented before any name is validated, then every name is validated in the order the CA returned its authorizations, then the `dns-01` TXT records are cleaned up. A validation failure for any one name stops the certificate — as with a single-method certificate, there is never a partial certificate — but the TXT records are still cleaned up before the attempt reports the failure.

### The verification rules step (web UI)

Rules are an ordered list; drag a row's grip to reorder, or use its **Move up**/**Move down** buttons. Each row picks its own **Method** (**DNS** / **Manual** / **HTTP** / **TLS-ALPN**) — a certificate can mix them, as in [Mixing methods](#mixing-methods). A DNS row shows a credential picker; an HTTP row shows **Served by** (**Server**, the default, or **Agent**) and, under Agent, a client picker plus an optional **Webroot** under **Advanced**; a TLS-ALPN row shows a client picker. A client picker only offers active clients that report the method's capability, unless an HTTP row has a webroot set, where any active client can write the token file. **Advanced** also holds propagation wait, resolvers, and (DNS only) a CNAME alias zone.

The wizard pre-fills one DNS rule per registered domain with the credential you last used for that zone (remembered locally) or, failing that, a credential an existing certificate already uses there. If no credential is known and your organization's catch-all rule already covers the name, no rule is added; otherwise the rule is added without a credential, and the **Coverage** list shows **No credential** — issuing stays blocked until you pick one, switch the row to another method, or use **Add credential**, which opens the provider picker and the credential form without leaving the wizard. **Add rule** copies the previous row's method.

The **Coverage** panel lists every certificate name with the rule and method that prove it (for example "HTTP · server" or "DNS · cloudflare-prod"), or **Catch-all: inherited from Org/Global** when none of the certificate's own rules match but the org or global catch-all does. A wildcard name that only resolves to an HTTP or TLS-ALPN rule shows **Wildcards need a DNS method** — see [Verification methods](#verification-methods). A name with neither is flagged and blocks **Next**.

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
- `useAri`: use the CA's ACME Renewal Information window when it is earlier — see [ARI](#ari).
- The scheduler checks every 5 minutes. **Renew now** enqueues immediately; it reports `enqueued: false` if an attempt is already queued or running.

### Failures and backoff

A failed attempt sets `failureCount`, `lastError`, and the next try to `min(5 min · 2^(failures−1), 24 h)` ±20%. When the CA answers `rateLimited` with `Retry-After`, the next try is no earlier than that. A failed renewal leaves a still-valid certificate `active`. A rate-limit ledger failure (see [Rate limits](#rate-limits)) is the one exception: the next try is scheduled exactly at the window's expiry, not by this backoff.

## CAA

Before any order, CertForge checks each name's CAA records itself: for each SAN, strip a leading `*.`, then climb labels from the name up to and including its registered domain, stopping at the first label with any CAA records — exactly the lookup RFC 8659 §5.3 describes. If that record set does not permit the CA (via `issuewild` for a wildcard name, `issue` otherwise, or an unrecognised critical property), the attempt fails before contacting the CA at all, with `urn:ietf:params:acme:error:caa` and a message naming the record and a CAA line to add.

This is a convenience only — **the CA always re-checks CAA itself during the real order**; disabling it here only saves a doomed order, it never lets an actually-forbidden name through. Turn it off with **Check CAA records** in [Settings → Issuance](configuration.md#issuance); a certificate has no per-certificate override. When the CA's directory publishes no `caaIdentities` (or a CA kind, Phase 5, that publishes none at all), the step succeeds without evaluating CAA — there is nothing to compare records against.

## Rate limits

Before every order, CertForge checks its own local record of what it has sent this CA — `new_order` (once per attempt), `cert_issued` (once per registered domain, on success) and `failed_validation` (once per registered domain, on a `unauthorized`, `dns`, `connection`, `incorrectResponse`, `tls` or `caa` failure) — against four trailing-window limits, defaulting to Let's Encrypt's own published limits: 50 certificates per registered domain per week, 5 duplicate (identical name set) certificates per week, 5 failed validations per registered domain per hour, 300 new orders per CA per 3 hours. Set to `0` to disable a limit; change them under [Settings → Issuance](configuration.md#issuance).

This is only an approximation of the CA's real limits: it is tracked **per CA entry, not per ACME account**, so two CA entries pointing at the same real CA (or an account shared outside CertForge) are not counted together, and a CertForge instance is never the CA's only client. A CA using the `letsencrypt-staging` preset is recorded but never enforced, since that CA does not itself rate-limit; any other directory (including a custom Pebble instance used for testing) is enforced like production, so a test run that needs to issue past the built-in limits raises them in settings instead.

When a limit is reached, the attempt fails at the `rate_ledger` step with `urn:ietf:params:acme:error:rateLimited` and a message naming the limit, the current count and the retry time; unlike an ordinary failure, the next attempt is scheduled exactly when the window clears (the oldest counted event's window expiry), not by the usual exponential backoff — though a longer `Retry-After` from the CA itself still wins. Lowering a limit in settings takes effect at once, but a count already above the new, lower maximum can take more than one window to fall back under it: each window boundary only drops the single oldest counted event, not the whole backlog.

`GET /orgs/{orgId}/rate-ledger?ca=<id>` (also shown on the CA's page) reports the current count, limit and reset time for each: one `certsPerRegisteredDomainPerWeek` and one `failedValidationsPerHour` entry per registered domain the org has a certificate for against this CA (whether it has ever issued there or only ever failed), one `newOrdersPer3Hours` entry for the CA as a whole, and — only when `certificate=<id>` is also given — one `duplicateCertsPerWeek` entry for that certificate's exact name set. Every count is CA-wide (it is the CA's own limit, shared by every org using that CA entry); only which registered domains are shown is scoped to the calling org's own certificates.

## ARI

Turn on **Use ARI** in a certificate's renewal policy (or its inherited default) to let the CA itself suggest when to renew, via [ACME Renewal Information](https://www.rfc-editor.org/rfc/rfc9773.html) (RFC 9773). CertForge fetches the window (`start`, `end`) for a managed certificate's current version right after it issues, and again every 6 hours for every certificate that has ARI on; the CA's own `Retry-After` (or 6 hours, when it gives none) paces how often a certificate is actually polled.

A fetched window only ever moves the certificate's scheduled renewal **earlier**, never later: when the window's end is before the date the ordinary renewal policy (days/percent of lifetime) already picked, the certificate renews at a uniformly random instant inside the window instead; otherwise the ordinary policy date stands. A certificate whose last attempt failed is left on its backoff schedule — the window is still fetched and shown, but does not move `nextRenewAt` until the certificate succeeds again. The CA's directory not publishing a `renewalInfo` endpoint at all (still common) is not an error shown anywhere; the certificate simply keeps its ordinary renewal schedule.

The fetched window is shown on the certificate as `ariWindow` (`start`, `end`, `checkedAt`), `null` until a poll has actually run. Only a managed certificate is ever polled; an unmanaged (imported or uploaded) certificate never has ARI applied.

When useAri is on and the certificate is renewing a version this CertForge instance actually issued (not an import or upload) against the very CA the new order is going to, the order also names it as the certificate being replaced (`replaces`), so the CA can waive rate limits that apply to a renewal. If the CA disagrees (`alreadyReplaced`, most often because a different order already claimed it), lego drops `replaces` and retries the order once on its own; CertForge does not retry this itself.

## Attempts

Each attempt records a step timeline: `caa`, `rate_ledger`, `account`, `order`, `challenge <name>`, `finalize`, `store`, each `running`, `success`, `failed`, `skipped` or `waiting_manual`, plus a log, the ACME error type (for example `urn:ietf:params:acme:error:rateLimited`) and `retryAfter`.

The certificate's **Attempts** tab shows every attempt, newest first, as a step timeline. The failing step (if any) opens by default with its message; the raw log is collapsed behind **Raw log**, which adds a search box and a copy button once opened. While an attempt is `running` the tab polls every 2 seconds; once none is, it slows to 30 seconds, and never polls while the tab is hidden. `caa` and `rate_ledger` show as **CAA check** and **Rate limits**; a skipped step's reason (for example "disabled in settings") is shown muted inline. A failed **Rate limits** step also shows the current [rate-ledger](#rate-limits) usage for the certificate's CA: one row per limit, with its scope, a `count/max` meter, and when it resets; a limit with no maximum reads "No limit", and a staging (unenforced) CA shows a **Counted only** chip instead of blocking.

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

`GET .../versions/{vid}/download?format=pem&parts=...` (`format` is `pem` or `der`, default `pem`). Parts: `cert`, `chain`, `fullchain`, `key`, `combined` (fullchain + key). One part returns a raw file; several return a zip (`privkey.pem`/`privkey.der` and `combined.pem` with mode 0600). `key` and `combined` need the `keys:export` permission (global admin only) and every such download is written to the audit log before any byte is sent.

`POST .../versions/{vid}/export` packages a version as PKCS#12 or JKS instead, with the password (and, for `p12`, `encoding`, or for `jks`, `alias`) in the JSON request body — see [Export passwords](#export-passwords) for why. It needs `certs:read` and `keys:export`, the same as a key-bearing download.

The web UI's Download sheet offers all four formats, starting each PKCS#12 or JKS export with a generated 24-character password (copy it before downloading, or turn on **Use my own password**); a key-bearing selection shows a reminder that the export is recorded in the audit log.

### Formats

Four output formats:

- `pem`: `cert`, `chain`, `fullchain`, `combined` (fullchain + key), `key`, and `extra` (the leaf and chain of each layout's extra certificates, concatenated in order). One part returns a PEM file; several return a zip.
- `der`: `cert` → `cert.der`; `chain` → one `chain-N.der` file per chain certificate; `key` → `privkey.der` (PKCS#8). `fullchain` and `combined` are not available as DER, since each DER file holds exactly one certificate or key, not several concatenated together.
- `p12`: one password-protected `<name>.p12` holding the leaf, its chain, any extra certificates (as CA certificates, leaf and chain), and the key.
- `jks`: one password-protected `<name>.jks` Java keystore holding a private-key entry (leaf, key, chain) and a trusted-certificate entry per extra certificate and per extra chain certificate; the store password equals the key password, must be at least 6 characters, and must be ASCII (Java's own keystore format does not agree with this library on how a non-ASCII password hashes, so a non-ASCII password would produce a file Java/keytool cannot open with the same password).

`key`, `combined`, and every p12/jks export need the `keys:export` permission (global admin only) and are written to the audit log before any byte is sent, as `certificate.key_exported` with a `format` of `pem`, `der`, `p12`, or `jks`.

### Export passwords

Export (`POST .../export`) takes its password in the JSON request body instead of a query parameter, unlike download's `format`/`parts`: a GET's query string routinely ends up in proxy and browser history, access logs, and `Referer` headers, so a query-string password would leak far more readily than one that never leaves the body of a POST. The password is validated (1 to 128 characters; at least 6, ASCII-only, for JKS) but never stored, logged, put in a URL, returned by any read, or included in the `certificate.key_exported` audit event the export records — that event's `details` carries only `certificateId` and `format`.

A one-off export is not the only way to get PKCS#12 or JKS files: a layout can render a `p12`/`jks` file on every issuance, with its own stored password and up to 10 extra certificates bundled in — see [agent.md#file-layouts](agent.md#file-layouts).

## Upload

`POST /orgs/{orgId}/certificates/upload` stores an existing certificate — one you got some other way, not through CertForge's own issuance — as a certificate CertForge can deploy through the same grants, layouts and exports as any other. Send exactly one of:

- `certificatePem`: a PEM leaf certificate, optionally followed by its chain, plus an optional `privateKeyPem` (PKCS#1, SEC1 or PKCS#8; CertForge normalises whichever you send). A key you provide must match the leaf's public key.
- `pkcs12Base64`: a base64-encoded PKCS#12 bundle, plus its `password` if it has one. A PKCS#12 upload must contain a key — that is what the format is for; a certificate-only PKCS#12 bundle (a Java trust store, say) is not accepted, upload the certificate as PEM instead.

Omitting the key (`certificatePem` with no `privateKeyPem`) stores the certificate keyless — useful for a certificate whose key lives somewhere CertForge should not hold it, deployed through a layout that only ever needs `fullchain` (never `key`, `combined`, or a p12/jks file). Any chain you send is validated, not merely stored as given: a certificate repeated in the chain is dropped, the remaining entries are ordered by issuer regardless of how you submitted them, and each link must actually have signed the certificate above it — an unrelated or out-of-place certificate is a 422. The name and SANs come from the leaf certificate's own DNS SANs, preferring the leaf's own subject CN as the name when it is itself one of those SANs; a certificate with no DNS SAN at all (an IP-only leaf) is rejected, since CertForge's certificate model is DNS-name-based throughout. `POST .../certificates/{id}/versions/upload` adds a further uploaded version to the same certificate later (a renewal you did yourself, for example) — see [Unmanaged certificates](#unmanaged-certificates) for why this only ever works on a certificate upload created in the first place.

The web UI's **Upload PEM or PKCS#12**, under Certificates → Import, is a form over this same endpoint: a name, a PEM/PKCS#12 segmented choice, and either the certificate and key text or a `.p12`/`.pfx` file and its password.

## Import

`POST /orgs/{orgId}/certificates/import` (`multipart/form-data`) reads an acme.sh (`~/.acme.sh`) or certbot (`/etc/letsencrypt`) state directory — packed as a `.zip` or `.tar.gz`, either at the archive's root or under its usual top-level directory name (`.acme.sh/`, `letsencrypt/`) — and stores everything it finds as **managed** certificates: unlike an upload, CertForge takes over renewing an imported certificate from here on, against whichever CA you choose. Fields:

- `archive`: the `.zip` or `.tar.gz` file. Limits: 32 MiB compressed (the request body cap), 128 MiB uncompressed, 2,000 entries; anything else is a 413 (too large) or 422 (not a recognizable archive, or one of the other limits was hit). Zip-slip paths (absolute, or containing `..`) fail the whole archive; a symlink or anything else that is not a regular file is silently skipped rather than extracted.
- `caId`: the CA every imported certificate is recorded against from now on.
- `dryRun`: defaults to `true` — a preview that stores nothing. Set it to `false` to actually create the certificates.

The response is one `ImportItem` per certificate the archive holds, whether or not it was actually stored: `action` is `create` or `skip`, with `reason` explaining either (a dry run's `create` items say what *would* happen; `skip` covers a name already taken in this org, an unparseable or unusable certificate, or a chain that does not lead back to the leaf). A dry run and the real run that follows agree exactly, since both go through the same write and only differ in whether it commits.

acme.sh's `<domain>[_ecc]/` directories (matched on `fullchain.cer`, or `<domain>.cer` plus `ca.cer`) and certbot's `archive/<name>/certN.pem` generations (the highest `N` wins; `live/<name>/*.pem` is the fallback when `archive/<name>` has nothing) are both detected automatically — an archive is either one or the other, never both. Each certificate's name is the directory name from the archive (acme.sh's own domain, minus `_ecc`; certbot's own lineage name); its CertForge names (common name and SANs) come from the leaf certificate itself, the same way an upload's do. A directory with no key file imports keyless, same as an upload.

The CA needs an ACME account already registered in this org: the org's own default account when it belongs to `caId`, or the org's first account on that CA otherwise (`caId`'s override is always written; the account is only written when the org default does not already cover it). No account on `caId` at all is a 422. A whole import run — whatever it created — is recorded as one `certificate.import` audit event (created/skipped counts and the names actually created; a dry run is not audited, since nothing changed).

The web UI's **From acme.sh or certbot**, under Certificates → Import, is a form over this same endpoint: an archive dropzone, a CA combobox, a Preview that runs the dry run as a table of create/skip rows with each skip's reason, and an Import button that runs it for real.

## Unmanaged certificates

An uploaded certificate is **unmanaged**: CertForge stores it, can deploy it, and shows it in the same certificate list as everything else, but never renews it and never picks a CA, account or verification rule for it. `managed: false` on the certificate marks this; `nextRenewAt` is always `null`. **Renew now** and editing the certificate's definition both 409 "managed externally" — CertForge has nothing to renew or re-verify against, so both would be a no-op wearing the clothes of a real action. The one write CertForge accepts on an unmanaged certificate's material is `versions/upload`: add a version you renewed yourself, the same shape as the original upload. `versions/upload` in turn 409s on a still-managed certificate — it is not a way to hand CertForge a certificate you made outside of it while CertForge is still trying to renew the same names itself.

A grant, layout and deploy target work on an unmanaged certificate exactly as they do on a managed one, with one rule: a layout that renders a key (any part `key`/`combined`, or a p12/jks file), or a Traefik deploy target (which always renders `fullchain` + `key`), cannot be granted against a certificate whose current version has no stored key — 422 on `certificateId` if you try. Uploading a keyless version onto a certificate that already has such a grant is refused the same way (409), so a grant never silently starts failing to deploy because a later upload dropped the key it depended on.

The web UI marks an unmanaged certificate with a **Managed externally** chip, disables Renew now and Settings' Edit in favour of an **Upload new version** action, and shows "Not renewed here" in place of Next renewal.

