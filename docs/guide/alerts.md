# Alerts

CertForge raises an **event** when something needs attention: a certificate was issued or is about to expire, a renewal keeps failing, a deploy failed, an agent went offline, an external endpoint serves the wrong certificate, or a backup finished or failed. A **channel** sends those events to a place you read, such as a webhook, email, Discord, ntfy or Home Assistant. Open **Alerts** in the sidebar. It has three tabs: **Channels**, **Monitors** and **Events**.

## Before you start

- You need the `alerts:write` permission to add, change or test channels and monitors. Viewers can read all three tabs.
- Email channels need a mail server under **Settings → Integrations → Email (SMTP)**. See [SMTP](#smtp).
- Alerts belong to one org. A global admin can also make a channel that receives every org's events.

## Channels

A channel has a type, the settings of that type, a filter on which events it receives, and a minimum severity. An org can have up to 50 channels.

The **Channels** tab lists each channel as its name over a muted line: the type, a short destination (a host or the recipients, never a secret), the owner org when it is another org's, "All orgs" when set, and the kinds it receives ("All events" when unfiltered, with the severity floor in brackets when above Info). The next columns show **Last delivery** (a status chip and a relative time, or "Never") and an **Enabled** switch.

### Add a channel

1. Select **Add channel**.
2. Enter a **Name**, such as `ops-webhook`.
3. Pick a **Type**: **Webhook**, **Email**, **Discord**, **ntfy** or **Home Assistant**. The type cannot change later.
4. Fill in the settings for the type. They are listed in the sections below.
5. Under **Events**, pick which events to send. **All events** is selected when none are picked. Kinds are grouped as Certificates, Deployments, Clients, Monitors and Backups.
6. Leave **Enabled** on.
7. Optionally open **Advanced** to set **Minimum severity** (Info, Warning or Critical) and **All orgs**. Only a global admin can turn on **All orgs**.
8. Select **Save**.

Secret settings, such as a webhook URL or a token, show **Stored** after you save and are never shown again. Leave one alone to keep it. If you change a server or base URL on an ntfy or Home Assistant channel, you must enter the token or webhook ID again. This stops an old secret following the channel to a new address.

### Test a channel

Select **Send test** in the channel's sheet. CertForge sends a test event to that one channel and shows **Delivered** or **Failed**, how long it took, and any error. The button is disabled until the channel is saved and has no unsaved changes, because it tests the saved settings. A disabled channel can still be tested.

### Change or delete a channel

Select a row to open its sheet. The **Enabled** switch on the row pauses a channel without opening it. A disabled channel receives no events. To delete a channel, select **Delete** and type its name. Past deliveries stay in the event log.

### Choose which events a channel gets

A channel receives an event only if all three match:

- the event kind is in **Events**, or **Events** is empty;
- the event's severity is at or above **Minimum severity**;
- the event belongs to the channel's org, or the channel has **All orgs** on.

Events not tied to an org, such as backups, reach only **All orgs** channels. A test event goes to the tested channel only. See [the event reference](../reference/events.md#events) for every kind and its severity.

## Webhook

A webhook channel posts each event as JSON to a URL. The body and headers are in [the event reference](../reference/events.md#webhook-payload).

| Field | What it does | Default |
|---|---|---|
| **URL** | Where events are sent. Up to 2048 characters. Secret. | Required |
| **Authorization header** | Sent as the request's `Authorization` header, for example `Bearer <token>`. Secret. | None |
| **Extra headers** | Up to 20 name and value rows. A name that looks like a credential is refused. Use **Authorization header** for credentials. | None |
| **Signing secret** | A key of 16 to 256 characters. Signs each request so the receiver can check it. Secret. | Unsigned |
| **CA certificate (PEM)** | Extra trusted roots for a private endpoint. | None |

To check a signature, see [Verify a signature](../reference/events.md#signature).

## SMTP

An **Email** channel sends a plain-text message per event. The mail server is shared by all email channels and is set once, in **Settings → Integrations → Email (SMTP)**.

| Field | What it does | Default |
|---|---|---|
| **Recipients** | One to 20 addresses. | Required |
| **Subject prefix** | Added in front of the subject. | `[CertForge]` |

In **Settings → Integrations → Email (SMTP)**:

| Field | What it does | Default |
|---|---|---|
| **Host** | Mail server name. Email channels fail with "SMTP is not configured" while it is empty. | Empty |
| **Port** | Server port, 1 to 65535. | `587` |
| **Username** | Login name. Leave empty for no login. | Empty |
| **Password** | Login password. | Empty |
| **From address** | Sender address. Required once **Host** is set. | Empty |
| **Security** | `starttls`, `tls` or `none`. A username needs `starttls` or `tls`. | `starttls` |
| **Timeout (seconds)** | Per-connection timeout, 1 to 60. | `10` |

With `starttls`, a server that does not offer STARTTLS is an error, not a silent downgrade. To check the settings, save them, enter an address in **Send to** and select **Send test email**. The test uses the saved settings. When the **Base URL** under **Settings → General** is set, each email links to the org's events page.

## Discord

A **Discord** channel posts one embed per event to a Discord channel webhook. Create the webhook in Discord under **Server Settings → Integrations → Webhooks**, then paste it as **Webhook URL**. It must start with `https`. The embed's colour follows the severity. It never pings roles or `@everyone`.

## ntfy

An **ntfy** channel publishes the event summary to an [ntfy](https://ntfy.sh) topic.

| Field | What it does | Default |
|---|---|---|
| **Server** | ntfy server URL. | `https://ntfy.sh` |
| **Topic** | Topic to publish to. | Required |
| **Access token** | Sent as a bearer token. Leave empty for a public topic. Secret. | None |
| **CA certificate (PEM)** | Extra trusted roots for a self-hosted server. | None |

Priority follows severity: 3 for info, 4 for warning, 5 for critical. The tags are the severity and the kind, such as `warning,cert_expiring`.

## Home Assistant

A **Home Assistant** channel posts the [webhook JSON](../reference/events.md#webhook-payload) to `<Base URL>/api/webhook/<Webhook ID>`.

1. In Home Assistant, create an automation with a **Webhook** trigger and copy its ID.
2. In CertForge, add a channel of type **Home Assistant**.
3. Enter **Base URL**, for example `https://homeassistant.local:8123`, and the **Webhook ID**. The ID is secret and may use letters, digits, `_` and `-`, up to 128 characters.
4. Add **CA certificate (PEM)** if Home Assistant uses a private CA.
5. Save, then select **Send test**.

In the automation, read `kind`, `severity`, `resource` and `summary` from the JSON body.

## Events

The **Events** tab is the feed for the last 90 days, newest first, including events not tied to an org. Use the toolbar to filter. On narrow screens a **Filters** button opens it.

| Filter | Choices |
|---|---|
| **Kind** | Any number of kinds. Shows "All kinds", the kind's name, or "N kinds". |
| **Severity** | **All**, **Warning+** or **Critical**. This is a minimum, not a set. |
| **Time** | **Last 24 hours**, **Last 7 days**, **Last 30 days** or **All time**. |

Select **Clear filters** to reset. Columns are **Time**, **Severity**, **Kind**, **Resource**, **Summary** and **Deliveries**. **Resource** links to the certificate, client, monitor or channel. The **Deliveries** chip reads "Sent" or "N sent", "N pending", or "K of N failed", whichever is worst. Select it to see each channel with its attempts, time and error. It reads "None" when no channel matched. Pending deliveries keep the list refreshing. Select **Load more** for older events.

CertForge retries a failed delivery up to 12 times over about five hours before marking it failed. One failing channel never blocks another.

An agent waiting for approval raises a **Client awaiting approval** event when **Settings → Agents → Require approval** (`agents.requireApproval`) is on. It carries the verification code and hostname. Open the **Awaiting approval** card on the **Clients** page and compare the code with the one the agent logged. See [Clients](clients.md#approval).

## External monitors

A monitor checks which certificate a TLS endpoint serves, whether or not CertForge deployed it, and raises an event when that changes. Use it to catch a deploy that did not take effect or an expired certificate. An org can have up to 500 monitors.

### Add a monitor

1. Open **Alerts → Monitors** and select **Add monitor**.
2. Enter **Name** (unique in the org), **Host** and **Port**.
3. Pick a **Check interval**: **5 m**, **15 m**, **1 h**, **6 h** or **24 h**.
4. Pick an **Expected certificate**, or keep **Any CertForge certificate**.
5. Open **Advanced** to set **SNI**, the server name sent in the TLS handshake. It defaults to the host.
6. Leave **Enabled** on and select **Save**.

| Field | What it does | Default |
|---|---|---|
| **Host** | Hostname or IP, up to 253 characters. | Required |
| **Port** | TCP port. | `443` |
| **Check interval** | How often it runs, from 300 to 86400 seconds. Each run adds up to 10% jitter. | `1 h` |
| **Expected certificate** | The certificate this endpoint should serve. | Any CertForge certificate |
| **SNI** | TLS server name to send. | The host |

**Host** follows the same rule as channel URLs. Loopback and link-local addresses are refused unless **Allow loopback and link-local** is on under **Settings → Integrations → Notifications**. Private-network addresses are allowed. Cloud-metadata addresses are always refused.

The list shows the name, the **State**, the **Next check** and a refresh button for **Check now**. **Check now** runs a check at once. The monitor's sheet shows a **Last check** block with the fingerprint, issuer, expiry, expected certificate and any error. Changing the host, port, SNI or expected certificate resets the state to Unknown and checks again on the next pass.

A certificate that a monitor expects cannot be deleted. Change or delete the monitor first.

### States

| State | Meaning |
|---|---|
| Unknown | No check has finished yet. |
| OK | Reachable, the certificate matches, and it does not expire soon. |
| Mismatch | Reachable, but the certificate is not the expected one. |
| Expiring | Matches, but expires soon. The chip reads Expired once the date has passed. |
| Unreachable | Two checks in a row failed to connect, handshake or present a certificate. One failure keeps the previous state. |
| Paused | The monitor is disabled. |

With **Any CertForge certificate**, the endpoint must serve the current version of some certificate in the org. An endpoint CertForge knows nothing about therefore reads Mismatch until you pick the certificate it should serve. "Soon" is 14 days, or a third of the certificate's lifetime if that is shorter. When several apply, the order is Unreachable, Mismatch, Expiring, OK.

An event fires only when the state changes. **Monitor recovered** fires when a Mismatch, Expiring or Unreachable monitor returns to OK. A first successful check, from Unknown to OK, raises none. The check itself never fails on an untrusted chain. Trust errors appear in the event's `chainError` detail.

To delete a monitor, select **Delete** in its sheet and type its name. Past events stay in the log.

## Common problems

**Send test is disabled.** The channel is new or has unsaved changes. Save first.

**A test shows Failed with a blocked-address error.** The destination is loopback or link-local. Turn on **Allow loopback and link-local** under **Settings → Integrations → Notifications**, or use a private-network address.

**An email channel fails with "SMTP is not configured".** Set **Host** and **From address** under **Settings → Integrations → Email (SMTP)**.

**"Re-enter the secret" when saving.** You changed the server or base URL and left the secret alone. Enter the token or webhook ID again.

**A channel gets no events.** Check **Enabled**, **Events**, **Minimum severity** and **All orgs**. Backup events reach only **All orgs** channels.

**A monitor shows Mismatch for a host you manage.** It serves a certificate that is not the one expected. Redeploy, or pick the right **Expected certificate**.

**A monitor shows Unreachable.** Hover the chip for the last error. Check the host, the port and the address rules above.

**A certificate cannot be deleted.** A monitor expects it. The error names the monitors.

## See also

- [Event reference](../reference/events.md) for kinds, payloads, dedupe keys and signatures
- [Settings](settings.md) for SMTP, notifications and Prometheus sections
- [Clients](clients.md) for approving enrolments
- [Monitoring](../operations/monitoring.md) for health endpoints and Prometheus metrics
