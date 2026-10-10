# Troubleshooting

Server-side problems and agent connection errors are on this page. Problems specific to a feature are in that guide page's **Common problems** section; the index at the end links to each.

## Server

**The server exits at start with a message about the encryption key.** `CF_KEK`, `CF_KEK_FILE` or `CF_KEK_VAULT_ADDR` is missing, set twice, or has the wrong length or format. Set exactly one. See [the encryption key](../reference/configuration.md#the-encryption-key).

**The server refuses to start on an existing database.** The key does not match the one that sealed the data. Restore the original value of `CF_KEK` or `CF_KEK_FILE`. If you rotated the key, keep the old one as `CF_KEK_PREVIOUS` until re-encryption finishes. See [Key management](key-management.md).

**`/readyz` returns `503`.** Read the `checks` object. `database: failed` means Postgres is unreachable (check `CF_DATABASE_URL`). `kek: failed` means the encryption key check failed. `vault: failed` means the Transit key is unreachable. Details are in the server log. See [Monitoring](monitoring.md#health-endpoints).

**Actions succeed but leave no audit entry, and the log says `audit: unavailable`.** The encryption key check failed at start, so the server does not write audit events. Fix the key and restart. Downloading a private key fails with `500` in this state on purpose.

**A migration fails with `reserved slug "all"`.** An organization uses the slug `all`. Rename it and start again. See [Upgrades](upgrades.md#migrations).

**The server will not start: `a restore holds the database lock`.** A `certforge restore` is running against the same database. Wait for it to finish.

**`certforge restore` says a server is running.** Stop every `certforge serve` process on that database first. See [Backup](../guide/backup.md).

**`429 Too many requests` on login.** The per-address login limit was hit. It is set in **Settings → Authentication**. If every user shares one address, the proxy is hiding real addresses: add it under **Trusted proxies**.

**`503 Service busy` on login.** Four password hashes were already running. Retry after a second.

**`413 Payload too large`.** The request body is over 1 MiB. Certificate import allows 32 MiB.

**`/metrics` returns 404 or 401.** See [Monitoring](monitoring.md#common-problems).

**HTTP-01 challenges fail.** Port 80 for the certificate's name does not reach `/.well-known/acme-challenge/` on CertForge. See [Deploying](deploying.md#route-http-01-challenges).

## Agents

Agent messages appear in the agent's log. The server records agent events in the audit log and **Events**.

**The log says `the system clocks differ by more than a minute`.** The agent's clock and the server's differ by over 60 s. Enable time sync on both hosts.

**The log says `the server refused the request as a replay`.** A request was sent twice within 2 minutes, usually by a proxy retrying. Turn off proxy retries for `/agent/v1`.

**The log says `response is not signed and sealed by the CertForge server`.** Something other than CertForge answered, or a proxy rewrote the response. Check that the proxy forwards `Host` unchanged and passes the `Signature`, `Signature-Input`, `Content-Digest` and `Cf-*` headers. See [Deploying](deploying.md#put-a-reverse-proxy-in-front).

**The WebSocket never connects but plain requests work.** The proxy does not allow WebSocket upgrades. Enable them for `/agent/v1/ws`. The agent still syncs on its pull schedule without the socket.

**The socket reconnects about every 1000 messages.** This is by design: each session carries at most 1000 messages per direction, then the agent reconnects for fresh keys.

**The agent logs `ENROLMENT WAITING FOR APPROVAL`.** Approval is on. An administrator must open **Clients**, compare the verification code with the one in the log and approve. See [Clients](../guide/clients.md#approval).

**The agent says the verification code does not match.** The agent is not talking to the CertForge its token names, or the token is for another server. Do not approve. Check the **Agent URL** and DNS.

**Enrolment says an administrator rejected the request, or it expired.** Create a new token (or re-enrol the client) and start the agent again. Pending requests expire after **Approval window (hours)** (`pendingTtlHours`, default 24).

**Enrolment fails with `409`.** There are already 50 pending requests in the organization, or the client has left the pending state. Approve or reject the waiting requests, or re-enrol the client.

**The agent says the responder chain does not contain the CA pinned by the token.** The token pins a CA that the server does not present (for example after a CA retire). Create a new token. See [Key management](key-management.md#agent-ca-rotation).

**The client shows Revoked.** An administrator revoked it, or it was re-enrolled and this is the old certificate. The agent stops on a signed refusal or a sealed `revoked` message, never on an unsigned one. Re-enrol it.

**The client shows Offline but the agent runs.** The agent cannot reach the server within **Offline after (seconds)**. Check the Agent URL, the proxy and the clock.

**An agent behind a private proxy CA fails TLS.** Give the agent the CA with `SSL_CERT_FILE`, or set `CF_AGENT_TRANSPORT=proxy`. See [Agent reference](../reference/agent.md).

## Guide pages
Each guide ends with **Common problems**.

| Topic | Page |
|---|---|
| Install and first login | [Getting started](../guide/getting-started.md#common-problems) |
| Issuing and renewing | [Certificates](../guide/certificates.md#troubleshooting) |
| CAs and private CA | [Issuers](../guide/issuers.md#common-problems) |
| DNS-01, HTTP-01, TLS-ALPN-01 | [Challenges](../guide/challenges.md#common-problems) |
| Enrolment and approval | [Clients](../guide/clients.md#common-problems) |
| Running the agent | [Agents](../guide/agents.md#common-problems) |
| Deploy targets | [Delivery](../guide/delivery.md#common-problems) |
| Channels and monitors | [Alerts](../guide/alerts.md#common-problems) |
| Users and sign-in | [Access](../guide/access.md#common-problems) |
| Vault | [Vault](../guide/vault.md#common-problems) |
| Backup and restore | [Backup](../guide/backup.md#common-problems) |

## See also
- [Monitoring](monitoring.md), [Security model](security-model.md), [Deploying](deploying.md)
