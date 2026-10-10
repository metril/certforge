# Challenges

An ACME CA only issues a certificate after you prove you control each name. This proof is a challenge. Each certificate carries an ordered list of verification rules that say how to prove each name. A [private CA](issuers.md) needs no challenges.

## Before you start

- You need `certs:write` to edit rules and `dnscreds:write` to add DNS credentials.
- Pick a method per name:

| Method | Label | How it works | Who acts |
|---|---|---|---|
| `dns-01` | **DNS** | A TXT record at `_acme-challenge.<name>`. Works for wildcards. | CertForge, using a [DNS credential](#dns-01) |
| `manual-dns` | **Manual** | The same TXT record, added by you. Works for wildcards. | You, see [Manual DNS](#manual-dns) |
| `http-01` | **HTTP** | A token served on port 80. No wildcards. | CertForge (**Server**) or a client (**Agent**), see [HTTP-01](#http-01) |
| `tls-alpn-01` | **TLS-ALPN** | A special certificate on port 443. No wildcards. | A client, see [TLS-ALPN-01](#tls-alpn-01) |

## Write verification rules

Rules live in the wizard's **Verification** step and in **Settings → Issuance defaults** (as catch-all rules).

1. In the wizard, open **Verification**. CertForge adds one **DNS** rule per registered domain, using the credential you last used there or one an existing certificate uses.
2. In **Match**, type what the rule covers (see the table below).
3. Pick the **Method**. A **DNS** rule shows a credential picker; an **HTTP** rule shows **Served by**; a **TLS-ALPN** rule shows a client picker.
4. Select **Add rule** for more. A new rule copies the previous rule's method. Reorder with the grip (**Reorder rule N**) or **Move rule N up** and **Move rule N down**. Remove with **Remove rule N**.
5. Check the **Coverage** panel. Every name must show a rule.

For each name the first matching rule wins. A certificate's inherited catch-all rules (org, then global) come after its own.

| `Match` | Covers | Does not cover |
|---|---|---|
| `*` | every name | |
| `*.example.com` | `a.example.com`, `*.example.com` | `example.com`, `b.a.example.com` |
| `example.com` | `example.com`, `a.example.com`, `b.a.example.com`, `*.example.com` | `badexample.com` |

- **Order narrow rules first.** With `dev.example.com` above `example.com`, `x.dev.example.com` uses the first. Reversed, the second shadows it.
- **Apex and wildcard** (`example.com` plus `*.example.com`) share one TXT name, so the rule that matches the apex serves both.
- **A wildcard skips HTTP and TLS-ALPN rules** and uses the next rule that fits, because no CA offers those methods for wildcards. A zone rule using HTTP can sit above a more specific `*.example.com` DNS rule. It is an error only if a wildcard has no rule left.
- **Coverage** shows each name with its rule (for example "Rule 1: example.com → DNS · cloudflare-prod"). Other states: **Catch-all: inherited from Org**, **No credential**, **No client**, **Wildcards need a DNS method**, **No matching rule**, **IP names aren't supported**. Anything but a rule or catch-all blocks **Next**.
- **Advanced** on a rule holds **Propagation** (seconds), **Resolvers** and, for DNS, **CNAME alias zone**. See [Options](#options).

Limits: 50 rules per list.

## DNS-01

CertForge creates the TXT record through your DNS provider's API, waits for it to be visible, then lets the CA check it.

### Add a DNS credential

1. Open **Issuers → DNS credentials** and select **Add credential**.
2. In **Choose DNS provider**, search by name, code or alias. The list has **Credentials in this org**, **Recently used**, **Common** and **All providers**. See the [provider catalogue](../reference/dns-providers.md).
3. Enter a **Name** and the provider's fields. If the provider accepts several kinds of credential, choose one under **Authenticate with**. Rarely used fields sit under **Advanced**.
4. Select **Save credential**. A credential that relies on the server's own cloud identity (no fields, `AWS_ASSUME_ROLE_ARN`, `AWS_PROFILE` or an Azure method other than `env`) needs a global administrator; see [Security model](../operations/security-model.md#server-cloud-identity-for-dns-providers).

You can also select **Add credential** inside a rule's credential picker without leaving the wizard.

Secret fields are stored encrypted and never shown again. When you edit a credential, leave a secret untouched to keep it. If you change connection settings, re-enter the stored secrets. A global admin can show one stored value with the eye button beside it (`dnscreds:reveal`); this is audited. Anyone else sees the button disabled. Each secret input also has an eye to show what you are typing.

Some providers use the server's own environment credentials and show no fields. Providers marked unavailable in the picker cannot be used.

### Test a credential

On **DNS credentials**, select the test button on a row, enter a **Zone** (for example `example.com`) and select **Run test**. CertForge creates `_acme-challenge._certforge-test.<zone>`, waits 20 seconds, checks that the record is visible (every 5 seconds for up to 60 seconds, using your effective **Resolvers**), then removes it. **Works for <zone>** means the credential can write and the record is visible. A record that was created but never became visible reports that.

### Edit or delete a credential

Use the row's edit and delete buttons. **Used by N** counts the certificates and defaults whose rules use it; a credential in use cannot be deleted (remove those references first).

## HTTP-01

The CA fetches `http://<name>/.well-known/acme-challenge/<token>` on port 80.

- **Served by Server** (the default): CertForge answers itself, on the main HTTP listener, unauthenticated. It keeps each token for up to 10 minutes. The CA must reach CertForge on port 80 for the certificate's names, so route port 80 for those names to it. See [Reverse proxy](../operations/deploying.md).
- **Served by Agent**: the named client answers. It uses its own HTTP-01 listener (`CF_AGENT_HTTP01_LISTEN`) if it has one. Otherwise set **Webroot** (under **Advanced**) to an absolute directory, and the agent writes the token file there for another web server to serve. See [Challenge serving](agents.md#challenge-serving).

The client picker lists active clients that serve HTTP-01, or any active client when **Webroot** is set. In **Global** defaults, **Agent** and **TLS-ALPN** are disabled because global defaults have no clients; set them per org or certificate.

## TLS-ALPN-01

The CA connects to port 443 and a client answers with a self-signed certificate carrying the validation value. There is no server mode and no webroot. The named client runs the listener (`CF_AGENT_TLSALPN_LISTEN`). See [Challenge serving](agents.md#challenge-serving).

## Manual DNS

Use this when CertForge cannot reach your DNS API.

1. Start the issue. The rule is **Manual**.
2. When the attempt reaches it, the certificate page shows a card titled **TXT records for <name>** with each record's name, type, value and TTL, each with a copy button.
3. Add the records at your DNS host. **Copy all as zone lines** copies them ready for a zone file.
4. Wait for them to resolve, then select **I've added them** (needs `certs:issue`). The attempt checks propagation and continues.

The card shows "Add these before <time>". If nobody confirms within 1 hour, the attempt fails with `manual-dns: TXT records were not confirmed in time`, the records are dropped, and the next attempt shows fresh ones. Remove the old TXT records by hand.

## CNAME delegation

To keep DNS API credentials away from a production zone, point the challenge name at a zone you control with a CNAME:

```
_acme-challenge.www.example.com.  CNAME  www.example.com.acme.example.net.
```

Then on the rule open **Advanced**, set **CNAME alias zone** to `acme.example.net`, and use a credential for that zone. CertForge follows the CNAME. A missing or mismatched CNAME fails that name on its first propagation check with a clear message. The option exists for **DNS** rules.

## Mixing methods

One certificate can use several methods: `www.example.com` on DNS, `api.example.com` on HTTP and `mail.example.com` on TLS-ALPN. Each name's own rule decides, so there is nothing extra to set up.

CertForge places every DNS TXT record first, validates every name, then removes the records. If any name fails, no certificate is issued, and the TXT records are still cleaned up. Each name has its own propagation budget (its rule's **Propagation**, or its provider's default), so a slow Manual name does not extend a DNS name's wait.

## Options

| Field | What it does | Default |
|---|---|---|
| **Match** | Names the rule covers. | none |
| **Method** | **DNS**, **Manual**, **HTTP**, **TLS-ALPN**. | **DNS** |
| **Served by** | **Server** or **Agent** (HTTP only). | **Server** |
| **Webroot** | Directory the agent writes tokens to (HTTP via agent). | none |
| **Propagation** | Seconds to wait for the TXT record (DNS, Manual). | provider default |
| **Resolvers** | DNS servers for the propagation check: `host[:port]` or a DoH URL. Up to 10. | system resolvers |
| **CNAME alias zone** | Zone the CNAME points into (DNS). | none |

## Common problems

**Issuing is blocked and a name shows No credential.** The DNS rule has no credential. Pick one, switch the row to another method, or select **Add credential**.

**Wildcards need a DNS method.** The only rule that matches the wildcard is HTTP or TLS-ALPN. Add a DNS or Manual rule for it.

**"no verification rule matches <name> and no catch-all rule is configured".** Add a rule for the name, or a `*` catch-all in the defaults.

**The CA says the TXT record is missing (`dns`, `incorrectResponse`).** The record had not propagated. Raise **Propagation**, check **Resolvers**, or use a [DoH resolver](certificates.md#defaults-and-overrides) if your network intercepts port 53. Stale records at the same name can also cause it.

**The test works but the CA cannot see the record.** The CA queries the zone's authoritative servers. Check for split-horizon DNS and CNAMEs.

**No HTTP client is listed.** The client does not report HTTP-01. Set `CF_AGENT_HTTP01_LISTEN` on the agent, or set a **Webroot**.

**A manual certificate stays Pending.** It is waiting for **I've added them**. See [Manual DNS](#manual-dns).

More ACME errors: [Troubleshooting](certificates.md#troubleshooting).

## See also

- [Certificates](certificates.md), [Issuers](issuers.md), [Agents](agents.md)
- [DNS provider catalogue](../reference/dns-providers.md)
