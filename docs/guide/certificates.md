# Certificates

A certificate in CertForge is a definition (names, a CA, how to prove control of each name, renewal policy) plus every version issued from it. CertForge issues the first version, renews on schedule and keeps the old versions. Use this page to create, renew, download, import and revoke certificates.

## Before you start

- A CA must exist, and for an ACME CA an account on it. See [Issuers](issuers.md).
- For an ACME CA, each name needs a way to prove control: see [Challenges](challenges.md). A private CA needs none.
- Permissions: **certs:read** views, **certs:write** creates, edits, deletes and uploads, **certs:issue** renews and revokes, **keys:export** (global admin only) downloads private keys.

## Issue a certificate

1. Open **Certificates** and select **New certificate**. A four-step wizard opens: **Names**, **Verification**, **Options**, **Review**. The summary on the right updates as you go.
2. **Names**: paste names, separated by commas, spaces, semicolons or new lines. See [Names](#names).
3. **Verification**: check the rule CertForge pre-filled for each zone, or add rules. See [Challenges](challenges.md). For a private CA this step shows **Not needed**.
4. **Options** (optional): override any [default](#defaults-and-overrides) for this certificate.
5. **Review** (optional): set the **Certificate name** (it defaults to the common name) and check the names, coverage and options. Select **Issue certificate**.

You can select **Issue certificate** from the **Verification** step onwards. The fast path is paste names, check the credential, issue. CertForge then opens the certificate's **Attempts** tab with the new attempt running.

To start from an existing certificate, use **Duplicate** on its page (the wizard opens pre-filled, named "<name> copy"). To change one, open its **Settings** tab and select **Edit**. Saving a changed name list issues a new certificate; other changes apply at the next renewal.

## Names

A certificate has a common name plus any number of SANs (additional names).

- Names are lower-cased and de-duplicated. A certificate holds at most 100.
- Names group by registered domain, so `a.example.co.uk` groups under `example.co.uk`.
- A wildcard (`*.example.com`, leftmost label only) is marked **DNS only**: it can only be proven with DNS. A wildcard directly on a public suffix such as `*.co.uk` is invalid.
- An IP address is marked **IP**. CertForge cannot verify IP names, so the certificate would fail.
- A red outline marks an invalid name; hover its icon for the reason. Remove it to continue.
- The first valid name is the common name. To change it, select a chip's crown button or drag the chip onto **Common name**.

## Defaults and overrides

Every issuance field exists at three levels: global (**Settings → Issuance defaults → Global**), org (the **Org** tab there) and the certificate (the wizard's **Options** step). A field left unset inherits from the level above. Turn on **Override** to set a value for one certificate and **Reset to inherited** to remove it. A badge shows where each value comes from: **Cert**, **Org**, **Global** or **Default**. A changed default applies at the next renewal of every certificate that inherits it.

| Field | Default | Notes |
|---|---|---|
| **Certificate authority** | none | Issuance fails until one is set at some level. |
| **ACME account** | none | Must belong to the CA. Not needed for a private CA. |
| **Key type** | EC P-256 | Also EC P-384, RSA 2048, RSA 3072, RSA 4096. |
| **Renewal** | Percent, 33 | See [Renew a certificate](#renew-a-certificate). |
| **Preferred chain** | CA default | Issuer common name of an alternate chain, for example `ISRG Root X1`. |
| **Reuse key** | off | Keeps the private key across renewals. |
| **Must-Staple** | off | Adds the OCSP must-staple extension. ACME CAs only. |
| **Propagation wait** | provider default | Seconds to wait for DNS records, 0 to 3600. |
| **Resolvers** | system resolvers | DNS servers for propagation checks: `host`, `host:port` or a DoH URL such as `https://cloudflare-dns.com/dns-query`. Use DoH on networks that intercept port 53. |
| **Verification rules** | none | Catch-all rules appended after a certificate's own. The closest level that sets them replaces the rest; lists never merge. |

Unset **Propagation wait** lets each DNS credential's provider decide, so a provider's own timeout setting takes effect. Limits: at most 50 verification rules and 10 resolvers per list. The server rejects a save over a limit with 422, but a list that already exceeds it keeps working until you edit that list.

## Private CA issuance

When the effective CA is a [Built-in CA or Vault PKI](issuers.md), a certificate issues without ACME:

- The wizard marks **Verification** and **Coverage** as **Not needed**. Rules you did not touch are not sent.
- The `account`, `caa`, `rate_ledger` and per-name `challenge` steps show **Skipped** with "not used by private CAs".
- An account inherited from a default is dropped silently. An account set on the certificate itself is rejected with 422 ("account belongs to a different CA").
- Must-Staple is rejected (422) unless the value is unchanged from what is already stored.
- Leaf validity is capped by the CA's **Max leaf validity (days)** (Built-in CA) or **TTL** (Vault PKI).
- ARI never applies: **ARI** is ignored.

## Browse and manage certificates

**Certificates** lists the org's certificates. Each row shows the name (with a muted line: common name, CA, "N grants", other names), **Status**, **Validity** (a bar plus days left) and **Next renewal**. Below tablet width the rows become cards.

- Filter with **Status** (**All**, **Active**, **Pending**, **Failed**, **Expired**, **Revoked**) and the **Search certificates** box, which matches the certificate name or any of its names. Both are kept in the URL.
- Sort by **Name**, **Validity** or **Next renewal** from the column headers.
- **Save view** stores the current filters under a name; it appears as a button beside it, and `x` deletes it. Views live in your browser only.
- **Load more** fetches the next page.
- Open a certificate with its name link. Clicking anywhere else on a row selects it (shift-click selects a range). A bar shows "N selected" with **Renew** (needs `certs:issue`) and **Delete** (needs `certs:write`, type `delete` to confirm). If some rows fail, they stay selected and a message names them.
- **Import** (next to **New certificate**) offers [**From acme.sh or certbot**](#import) and [**Upload PEM or PKCS#12**](#upload).

Under **All orgs** the list is read-only and adds an **Org** column.

## Read a certificate page

The header shows the name, **Status**, the validity bar (issue to expiry, a hatched renewal window, a notch for today and the CA's [ARI](#ari) window as a bracket), **CA**, **Account**, **Next renewal** and any recent **Failures**. Actions: **Renew now**, **Download**, **Duplicate** and, in the **More actions** menu, **Delete** (type the certificate's name). A certificate waiting on manual DNS shows its [TXT records](challenges.md#manual-dns) above the tabs.

| Tab | Shows |
|---|---|
| **Overview** | Names by domain, verification coverage and the effective configuration with sources. |
| **Versions** | Every issued version: serial, validity, SHA-256 fingerprint, source, a **Current** chip, a **No key** chip for a keyless version, and a download button. |
| **Attempts** | Every attempt, newest first. See [Attempts](#attempts). |
| **Deployments** | Every client that holds this certificate: site, delivery, layout, target, state, installed version and **Redeploy**. See [Delivery](delivery.md). |
| **Settings** | The wizard's settings, read-only, with **Edit**. |

The page refreshes every 2 seconds while an attempt runs and every 30 seconds otherwise, never while the browser tab is hidden. **Delete** removes the definition, all versions and attempts; it does not revoke anything.

## Renew a certificate

CertForge checks for due renewals every 5 minutes. **Renew now** queues one immediately and opens **Attempts**; it does nothing if an attempt is already queued or running.

- **Percent** N renews when N% of the lifetime remains (33 means day 60 of a 90-day certificate).
- **Days** N renews N days before expiry (1 to 365; percent is 1 to 99).
- A renewal is never scheduled before half the lifetime has passed, or sooner than an hour from now.
- Turn on **ARI** to let the CA pull the date earlier ([below](#ari)).

A failed attempt retries after `min(5 min x 2^(failures-1), 24 h)` plus or minus 20%, or after the CA's `Retry-After` if that is longer. A still-valid certificate stays **Active** while its renewal retries. A [rate-limit](#rate-limits) failure retries exactly when the window clears.

## ARI

ARI (ACME Renewal Information, RFC 9773) lets a CA tell you when to renew, for example after a revocation event. Turn on **ARI** ("Use renewal info") in the **Renewal** field of a certificate or default.

CertForge fetches the window after each issue and every 6 hours after that, paced by the CA's own `Retry-After`. A window only moves renewal earlier: when it ends before the policy date, renewal happens at a random moment inside it. A certificate whose last attempt failed stays on its backoff schedule. A CA with no ARI endpoint is simply ignored. Only managed ACME certificates are polled. When renewing a version this CertForge issued, the order names the old certificate so the CA can waive rate limits.

## CAA

Before ordering, CertForge reads each name's CAA records (stripping `*.` and climbing labels up to the top-level domain, as RFC 8659 describes). If no record set authorises the CA, the attempt fails at **CAA check** with `urn:ietf:params:acme:error:caa` and names the record to add. The CA re-checks CAA itself, so this only saves a doomed order. Turn it off with **Check CAA records** under **Settings → Issuance defaults → Global → Checks and limits** (`caaCheck`, default on). There is no per-certificate override. If the CA's directory publishes no CAA identity, the step passes without checking.

## Rate limits

Before each order CertForge checks its own count of what it sent this CA, against four limits that default to Let's Encrypt's: 50 certificates per registered domain per week, 5 duplicate certificates (same names) per week, 5 failed validations per registered domain per hour, 300 new orders per CA per 3 hours. Set a limit to `0` to disable it, and change them under **Settings → Issuance defaults → Global → Checks and limits** (0 to 100000).

The count is per CA entry, not per ACME account, so it only approximates the CA's real limits. Concurrent attempts can overshoot by a little. A CA using the **Let's Encrypt (staging)** preset is counted but never blocked (**Counted only**).

When a limit is reached the attempt fails at **Rate limits** with `rateLimited`, naming the limit, the count and the retry time. A failed **Rate limits** step shows usage per limit as a `count / max` meter with its reset time.

## Attempts

Each attempt is a timeline of steps: **CAA check**, **Rate limits**, `account`, `order`, `challenge <name>`, `finalize`, `store`. Each is running, success, failed, skipped or waiting on manual DNS. The failing step opens by default; **Raw log** (collapsed) adds a search box and a copy button. A skipped step shows its reason.

## Revoke a version

On a certificate issued by a private CA, a version issued by CertForge has a **Revoke version** button in **Versions** (needs `certs:issue`). Pick a **Reason** (**Unspecified**, **Key compromise**, **CA compromise**, **Affiliation changed**, **Superseded**, **Ceased operation**) and confirm. Revoking cannot be undone. Revoking the current version also makes the certificate renew at once. See [Revocation](issuers.md#revocation) for what each CA kind does. ACME, imported and uploaded versions cannot be revoked here.

## Downloads

Select **Download** (header, or a version's button). The sheet has:

- **Version**: defaults to the current one.
- **Format**: **PEM**, **DER**, **PKCS#12** or **JKS**.
- **Parts** (PEM and DER): `cert`, `chain`, `fullchain`, `key`, `combined` (fullchain plus key). DER has no `fullchain` or `combined` because a DER file holds one item. One part downloads as a file, several as a zip.
- **Password** (PKCS#12 and JKS): a generated 24-character password with copy and regenerate buttons, or **Use my own password**. JKS needs 6 to 128 ASCII characters. PKCS#12 takes **Encoding** **Modern** or **Legacy**; JKS takes an optional **Alias**.

`key`, `combined`, **PKCS#12** and **JKS** need `keys:export` and a version that has a key. Each such download is recorded in the [audit log](audit.md) as `certificate.key_exported` before any byte is sent. A layout can also render PKCS#12 or JKS files on every issuance: see [File layouts](agents.md#file-layouts).

### Export passwords

The PKCS#12 and JKS password travels in the body of a `POST` request, not in the URL, so it never reaches proxy logs or browser history. CertForge never stores or logs it, and the audit event holds only the certificate id and format. Copy a generated password before you close the sheet; it is not shown again.

## Upload

Use **Import → Upload PEM or PKCS#12** to store a certificate you obtained elsewhere so CertForge can deploy it. The page asks for a **Name** and a **Format**:

- **PEM**: **Certificate** (the leaf, optionally followed by its chain) and an optional **Private key**. A key must match the leaf.
- **PKCS#12**: a `.p12` or `.pfx` **File** (up to 768 KiB) and its **Password**. It must contain a key.

Without a key the certificate is stored keyless: fine if it is deployed through a layout that only needs `fullchain`. The chain is validated and ordered; an unrelated certificate is rejected. Names come from the leaf's DNS SANs; a leaf with only IP SANs is rejected. Select **Upload**.

## Unmanaged certificates

An uploaded certificate is **unmanaged** (a **Managed externally** chip). CertForge stores and deploys it but never renews it or edits its definition, so **Renew now** and **Edit** are disabled and **Next renewal** reads "Not renewed here".

To add a version you renewed yourself, select **Upload new version**. A leaf that is not yet valid is rejected, and so is one that expires before the current version; turn on **Allow an older certificate** to accept that rollback. A layout or Traefik target that needs a key cannot be granted on a keyless certificate, and uploading a keyless version over such a grant is refused.

## Import

Use **Import → From acme.sh or certbot** to take over an existing setup. Unlike an upload, CertForge then **renews** the imported certificates.

1. Archive your acme.sh state (`~/.acme.sh`) or certbot state (`/etc/letsencrypt`) as `.zip`, `.tar.gz` or `.tgz`. It may sit up to four folders deep. Limits: 32 MiB, 128 MiB unpacked, 2000 entries.
2. Drop the file in **Archive** and pick the **CA** that will renew them. That CA needs an ACME account in this org.
3. Select **Preview**. The table lists each certificate with **Create** or **Skip** (and the reason, such as a name already in use), expiry, issuer and **Key** or **No key**.
4. Select **Import N certificates**.

A certificate without a key file imports keyless. The whole run is one `certificate.import` audit event.

## Troubleshooting

A failed attempt shows a one-line explanation and a link here.

| ACME error | Meaning | What to do |
|---|---|---|
| `rateLimited` | The CA's rate limit was reached. | Wait for the retry time; avoid re-issuing identical names. |
| `dns`, `incorrectResponse` | The CA saw a missing, stale or wrong TXT record. | Check the record, [CNAME delegation](challenges.md#cname-delegation) and **Propagation wait**. |
| `unauthorized` | The CA rejected the proof. | Check the rule that covers the name. |
| `connection` | The CA could not reach the validation target. | Check the route and firewall for port 80 (HTTP-01) or 443 (TLS-ALPN-01). |
| `caa` | A CAA record forbids this CA. | Add the CA's identifier to the domain's CAA record. |
| `rejectedIdentifier` | The CA will not issue for this name. | Remove the name or use another CA. |
| `externalAccountRequired` | The CA needs EAB. | Add the key ID and HMAC key on the CA. |
| `accountDoesNotExist` | The CA does not know the account. | Register the account again. |
| `malformed` | The CA rejected the request. | Open **Raw log** for the field. |
| `badNonce`, `serverInternal`, `orderNotReady` | Transient. | CertForge retries with backoff. |

Any other error shows as "The CA returned `<type>`"; open **Raw log**.

**Issuing is blocked in the wizard.** A name shows **No credential**, **No client** or **No matching rule**. Pick a credential or client, change the method, or add a catch-all rule.

**The attempt fails with "no verification rule matches".** A name matched no rule and no catch-all exists. Add a rule or a default.

**A pending certificate never finishes.** It may be waiting on [manual DNS](challenges.md#manual-dns); confirm the records within an hour.

## See also

- [Issuers](issuers.md), [Challenges](challenges.md), [Delivery](delivery.md)
- [Issuance settings](../reference/configuration.md#issuance-defaults)
- [Audit log](audit.md)
