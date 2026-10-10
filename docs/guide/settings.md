# Settings

**Settings** (last item in the sidebar) holds the server-wide configuration. It has seven sections, listed down the left of the page. This page tells you what each section is for and where to read more. Every field, default and bound is in [Configuration](../reference/configuration.md).

## Before you start

- Anyone can read most sections. Changing a server-wide section needs the global **Admin** role; without it the **Save** button is disabled and its tooltip names the permission.
- Plain sections have a **Save** button and, once you edit a field, **Discard changes**. A saved change takes effect immediately, with no restart.
- Secret fields (passwords, tokens, client secrets) are write-only. A stored secret shows as stored; leave it alone to keep it, or use **Replace** to set a new one.
- **Access** is hidden if your role cannot read users anywhere.

## General

Open **Settings → General**.

- **Base URL** (`general.baseUrl`): the public address of CertForge. It is used in links in notifications and in the CRL address of private CAs. The setup wizard sets it.
- **Organizations**: create, rename and delete organizations, and manage each one's **Sites**. See [Access](access.md#create-an-organization-and-sites).

## Access

**Settings → Access** has three tabs: **Users**, **Role bindings** and **API keys**. They are covered in [Access](access.md). The tab and its filters are kept in the URL.

## Authentication

**Settings → Authentication** configures single sign-on, session length, trusted proxies, login rate limits and API key limits. It also shows the **Redirect URI** to register at your identity provider, a **Test connection** button, and **Group mappings**. See [Access](access.md#single-sign-on).

## Issuance defaults

**Settings → Issuance defaults** sets the values new certificates start with: the certificate authority, ACME account, key type, renewal timing, preferred chain, key reuse, Must-Staple, DNS propagation wait, resolvers and verification rules.

A **Scope** switch picks **Global** or **Organization**. The most specific value wins: a certificate's own setting, then its organization's, then the global one. Each field shows a source badge (Global, Organization or Certificate) so you can see where its value comes from. A change applies at each certificate's next renewal. **Reset** returns a global field to the value CertForge ships with.

The **Global** scope also has a **Checks and limits** card with **Check CAA records** and the local rate limits for certificate authorities. See [Certificates](certificates.md) for how defaults apply when you issue.

## Agents

**Settings → Agents** controls how client agents enrol and stay connected.

| Field | What it does | Default |
|---|---|---|
| **Agent URL** (`agents.agentUrl`) | The address agents dial; it goes into every enrolment token. Only new enrolments pick up a change | `https://<host of CF_BASE_URL>:8443` |
| **Listener names** (`agents.listenerNames`) | Extra DNS names and IP addresses on the agent listener's certificate | none |
| **Enrolment token lifetime (hours)** (`agents.tokenTtlHours`) | How long a new client's one-time token stays valid | 24 |
| **Require approval** (`agents.requireApproval`) | New agents wait for an administrator to compare verification codes and approve. Off: any valid token enrols at once | on |
| **Approval window (hours)** (`agents.pendingTtlHours`) | How long a request waits for approval, and how long an approved agent has to collect its certificate. Greyed out when approval is off | 24 |
| **Agent certificate lifetime (days)** (`agents.agentCertDays`) | Lifetime of an agent's identity certificate; agents renew at two thirds | 90 |
| **Heartbeat interval (seconds)** (`agents.heartbeatSeconds`) | How often agents report installed files for drift detection | 60 |
| **Offline after (seconds)** (`agents.offlineAfterSeconds`) | A client not seen for this long shows as offline | 180 |

Below the form, the **Listener certificate** card shows the names, expiry and issuing CA of the certificate on the agent port. The **Agent certificate authorities** card lists the CAs that sign agent identities, with **Rotate** to add a new one and **Retire** to stop trusting an old one once no agent still uses it. The steps are in [Key management](../operations/key-management.md#agent-ca-rotation). Agent setup is in [Clients](clients.md) and [Agents](agents.md).

## Integrations

**Settings → Integrations** has four cards.

| Card | What it is for |
|---|---|
| **Vault** | How the server reaches Vault or OpenBao for Vault PKI CAs and Vault KV targets: address, namespace, authentication method, CA bundle, timeout. **Test connection** logs in with the values in the form and saves nothing. See [Vault](vault.md) |
| **Email (SMTP)** | The mail server for email channels. **Send test email** sends one message with the saved settings, so save first |
| **Notifications** | Settings shared by every channel: whether loopback and link-local addresses are allowed, the expiry warning window and the renewal failure threshold. See [Alerts](alerts.md) |
| **Prometheus** | Turns on `/metrics` behind a bearer token. When enabled, the card shows the scrape URL and a ready scrape config. See [Monitoring](../operations/monitoring.md) |

If the server's encryption key lives in Vault Transit, the card also shows an **Encryption key** line with the Vault address. That key is set by environment variables, not here.

## Backups

**Settings → Backups** has three parts.

- **Backups** status card: the last result (**Succeeded**, **Failed** or **Never**), archive size, when the next scheduled backup is due, and **Back up now**, which downloads an encrypted archive.
- **Schedule**: **Off**, **Daily** or **Weekly**, how many archives to keep, and the directory they are written to.
- **Encryption key**: a one-line **Key check OK**, expanding into a progress list while an older key is configured or a re-encryption runs, with **Re-encrypt now**.

Restoring is done on the command line with the server stopped; there is no restore button. See [Backup](backup.md) and [Key management](../operations/key-management.md).

## Common problems

**Save is disabled.** You need the global **Admin** role for server-wide sections. Hover the button to see the permission.

**A secret field reads as stored but I need to change it.** Use **Replace**. For SMTP and Vault, changing the host, port, address or namespace means you must enter the secret again, because a stored secret is not sent to a different server.

**My Agent URL change did not move existing agents.** Already enrolled agents keep the URL they enrolled with. Re-enrol them to move them ([Clients](clients.md)).

**The Agents section says the listener is not running.** The agent listener failed to start; check the server log for the cause and restart the server after fixing it.

## See also

- [Configuration](../reference/configuration.md): every field, default and bound.
- [Access](access.md)
- [Overview](overview.md)
