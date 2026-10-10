# Clients

A client is one host that CertForge delivers certificates to. You create it in the UI, give its agent a one-time token, and approve the agent when it asks to join. After that you grant it certificates. This page covers creating, approving, re-enrolling and revoking clients. For the agent itself, see [Agents](agents.md).

## Before you start

- You need the `clients:write` permission in the organization to create, approve, re-enrol, revoke or delete clients. `clients:read` is enough to look. See [Access](access.md).
- Agents must reach the server. The default address is `https://<your host>:8443`. Behind a reverse proxy, see [Agents: Behind a proxy](agents.md#behind-a-proxy).

## Enrolment

Enrolment gives the agent its identity: a key it creates itself, and a certificate from CertForge's agent CA.

1. Open **Clients** and choose **Enrol client**.
2. Enter a **Name** (unique in the organization). Optionally pick a **Site**; a site only groups clients for filtering and never limits access.
3. Choose **Create token**. The page shows the **Token**, the **Agent URL** and when the token **Expires**. The token is shown once and is never stored in your browser.
4. Under **Run with**, pick **docker run** or **Compose**, copy the snippet, and run it on the host. Edit `CF_WRITE_ALLOW` and the mount to match the directory your certificates go to. Other ways to run the agent are on the [Agents](agents.md#running-with-docker) page.
5. The panel below the token waits for the agent and refreshes by itself. It reads **Waiting for agent**, then **Agent enrolled. Awaiting approval.** once the agent has used the token.
6. [Approve the agent](#approval). When it connects, the panel shows the host and offers **Grant certificate** and **Open client**.

The token looks like `cf1.<agent URL>.<CA fingerprint>.<secret>`. It carries the server address and the fingerprint of the agent CA, so the agent can tell it is talking to your server. It works once and expires after the **Enrolment token lifetime (hours)** setting (`agents.tokenTtlHours`, default 24). If it expires, the panel shows **Token expired** and a **New token** button.

The agent stores its key and certificate in its data directory (`/data` in the image). Keep that volume: it is the agent's identity, and the token is needed only until enrolment finishes.

## Approval

By default a valid token is not enough. The agent also needs an administrator to approve it. This stops a stolen token from enrolling a host you do not control.

### Approve an agent

1. When the agent starts it logs a line like this and waits:

   ```
   WARN ENROLMENT WAITING FOR APPROVAL: ... verification_code=ABCD-EFGH
   ```

   For a container, read it with `docker logs certforge-agent`.
2. In CertForge, the **Clients** item in the sidebar shows a count, and the **Clients** page shows an **Awaiting approval** card. **Overview** lists the same agent under **Needs attention** with a **Review** link. If you are on the enrolment page, its panel has a **Review** button too.
3. Choose **Review**. The **Approve agent** dialog shows the client, site, hostname, OS and architecture, agent version, source IP, when it was requested and when it expires, and a **Verification code**.
4. Compare the code with the one in the agent log. All 8 characters must match. Then switch on **Code matches the agent log** and choose **Approve**.
5. The agent collects its certificate and connects within a few seconds.

The code comes from the agent's new key and your server's CA. A different code means another host used the token, or something between the agent and the server is altering traffic. In that case choose **Reject**.

### Reject a request

Choose **Reject** in the dialog, or the **Reject** icon on the card. The agent is refused and its token is spent. To try again, use the **New token** button in the confirmation message, or **Re-enrol** on the client's **Settings** tab.

### Request lifetime

- A request waits for the **Approval window (hours)** setting (`agents.pendingTtlHours`, 1 to 168, default 24). After that its row shows **Expired**; choose **Dismiss** to remove it, then issue a new token.
- After you approve, the agent has the same window to collect its certificate.
- An organization holds at most 50 requests waiting for approval. Further enrolments are refused until some are decided or expire.
- Anyone with `clients:write` can decide a request. If someone else got there first, the dialog says **Someone else already handled this request.**

### Turn approval off

Switch off **Require approval** (`agents.requireApproval`) under **Settings → Agents**. Then any valid token enrols at once and no code is checked. **Approval window (hours)** is greyed out while approval is off. Leave approval on unless tokens never leave a trusted channel.

## Client states

The list shows two separate readings for each client.

| Reading | Values | Meaning |
|---|---|---|
| **Status** | **Pending** | Not enrolled yet, waiting for approval, or waiting for a new token after Re-enrol. |
| | **Active** | The agent holds a certificate. |
| | **Revoked** | The agent is refused. The client is kept for its history. |
| **Connection** | **Online** | The agent is connected, or reported within the **Offline after (seconds)** setting (default 180). Pull-only agents count too. |
| | **Offline** | Seen before, not within that window. It catches up when it reconnects or pulls. |
| | **Never connected** | Enrolled or created, never seen. |
| | **Revoked** | Shown for revoked clients. |

On a client's page the header says **Connected** for a live connection, **Online (pull)** for an agent that pulls without one, and **Offline since** a time.

## Find clients

**Clients** lists each client with its name (over a muted line of hostname, site, agent version, grants, drift and failed counts), **Status**, **Connection** and **Last seen**. Narrow the list with the **Status** control (**All**, **Active**, **Pending**, **Revoked**), the **Site** filter and the search box. Sort by name, status or last seen, and save views. Below medium width the list becomes cards. Under All organizations the list is read-only and adds an **Org** column.

## Client detail

Open a client to see its tabs: **Certificates** (grants and their deployment state), **Hooks** (hook run history), **Activity** (audit events that mention the client) and **Settings**. The header shows hostname, **Site**, **Agent** version and platform, **Agent certificate** expiry (highlighted within 14 days) and the capabilities the agent reported.

Grant certificates from the **Certificates** tab with **Grant certificate**. Grants, layouts, deploy targets and redeploys are explained in [Delivery](delivery.md). Hooks are in [Agents](agents.md#hooks-and-the-allowlist).

## Re-enrol a client

Use this after rebuilding the host, or when the agent's certificate has expired.

1. Open the client, then **Settings**.
2. Next to **Re-enrol**, choose **Re-enrol**. Type the client's name to confirm.
3. Copy the new token from the **New token for** dialog and give it to the agent. Changing `CF_AGENT_TOKEN` and restarting is enough: the agent enrols again whenever its configured token differs from the one it enrolled with.
4. [Approve](#approve-an-agent) the new request.

Until the agent enrols again, its old certificate is refused and its connection is closed. Pending requests of the client are discarded. A revoked client cannot be re-enrolled; create a new one.

## Revoke or delete a client

- **Revoke** (client **Settings**, type the name to confirm): the agent is refused from then on and disconnected. Files already on the host stay. Grants still waiting for the agent to remove files are dropped.
- **Delete**: removes the client, its grants and its hook history. Only revoked clients and clients that never enrolled can be deleted.
- **Save** on the same tab renames a client or moves it to another site.

## Options

| Setting (Settings → Agents) | What it does | Default |
|---|---|---|
| **Enrolment token lifetime (hours)** (`agents.tokenTtlHours`) | How long a new token works. | 24 |
| **Require approval** (`agents.requireApproval`) | Agents wait for an administrator. | on |
| **Approval window (hours)** (`agents.pendingTtlHours`) | How long a request waits, and how long an approved agent has to collect. | 24 |
| **Agent URL** (`agents.agentUrl`) | The address put into every new token. Only new tokens change; enrolled agents keep theirs. | `https://<host of CF_BASE_URL>:8443` |

Bounds and the remaining agent settings are in [Configuration](../reference/configuration.md#agents).

## Common problems

**The token is refused as invalid, used or expired.** Tokens work once and expire. Choose **Re-enrol** for a new one.

**Nothing appears under Awaiting approval.** You need `clients:write` to see the card. The agent may also be unable to reach the server: read its log, and see [Agents: Troubleshooting](agents.md#common-problems).

**The agent says an administrator rejected it, or the request expired.** Issue a new token with **Re-enrol** or **New token**.

**The verification codes differ.** Do not approve. The agent aborts on its own when the server's code does not match its own calculation; a mismatch you see in the dialog means another host holds the token. Reject and issue a new token.

**Enrolment is refused because too many requests are waiting.** Decide or dismiss the requests on the **Awaiting approval** card.

**Approving says the request was already handled.** Another administrator decided it. Reload the list.

## See also

- [Agents](agents.md): run the agent, hooks, file layouts, pull mode.
- [Delivery](delivery.md): grants, deploy targets, redeploy.
- [Agent reference](../reference/agent.md): environment variables, transport, limits.
- [Audit log](audit.md): `client.enrol_requested`, `client.enrol_approved`, `client.enrol_rejected`, `client.enrolled`.
- [Events](../reference/events.md): `client.pending_approval` raises an alert.
