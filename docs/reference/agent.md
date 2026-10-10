# Agent reference

Environment variables, commands, files, transport modes and protocol limits for `certforge-agent`. For how to use it, see [Agents](../guide/agents.md).

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `CF_AGENT_DATA` | `/data` | Data directory for key, certificate, CA bundle and state. Created with mode 0700. |
| `CF_AGENT_TOKEN` | none | Enrolment token. |
| `CF_AGENT_TOKEN_FILE` | none | File holding the token, for example a Docker secret. Used when `CF_AGENT_TOKEN` is empty. `run` waits for the file to appear, checking every 5 seconds. |
| `CF_AGENT_TRANSPORT` | `auto` | Which TLS server certificates the agent accepts: `auto`, `mtls` or `proxy`. See [Transport](#transport). Any other value is an error. |
| `SSL_CERT_FILE` | system roots | PEM file of CA certificates that replaces the system roots. Use it when a proxy's certificate comes from a private CA. Read by the Go runtime. |
| `CF_HOOK_ALLOW` | empty (hooks off) | Colon-separated absolute paths of executables hooks may run. Must be clean absolute paths. |
| `CF_WRITE_ALLOW` | empty (every deploy fails) | Colon-separated absolute directory prefixes the agent may write or remove files under. `/` is rejected. |
| `CF_AGENT_PULL_INTERVAL` | `0` | Reconcile on this schedule too, for example `15m`. `0`, or a duration of at least `1m`. `0` means only on server nudges and at connect. |
| `CF_AGENT_HTTP01_LISTEN` | empty (off) | `host:port` of the agent's own http-01 listener, for example `:8080`. Port 1 to 65535. |
| `CF_AGENT_TLSALPN_LISTEN` | empty (off) | `host:port` of the agent's tls-alpn-01 listener, for example `:5001`. Port 1 to 65535. |

An invalid value stops the agent with exit code 2.

## Commands

| Command | What it does |
|---|---|
| `certforge-agent run` | Enrol if needed, connect, reconcile on every nudge, send heartbeats, renew, reconnect with backoff. The container default. |
| `certforge-agent enroll --token <token>` | Enrol and exit. Without `--token` it uses `CF_AGENT_TOKEN` or `CF_AGENT_TOKEN_FILE`. Waits for approval when approval is required. |
| `certforge-agent pull` | Renew if due, reconcile once over plain requests, report, send one heartbeat, exit. No connection. |
| `certforge-agent status` | Print client id, Agent URL, certificate serial and expiry, revision and grant count. Prints `Not enrolled` before enrolment. |
| `certforge-agent version` | Print the version. |

Exit codes: 0 success, 1 failure (including a revoked client), 2 bad usage or configuration.

`run` reconnects with jittered backoff from 1 to 60 seconds. It stops with an error only when the server refuses the client (revoked or re-enrolled).

## Files in the data directory

| File | Mode | Content |
|---|---|---|
| `agent.key` | 0600 | The agent's ECDSA P-256 private key. Created once and reused. |
| `agent.crt` | | The agent certificate. Renewed at two thirds of its lifetime; the key stays the same. |
| `ca.pem` | | The agent CA bundle. Updated on renewal and on trust updates. |
| `state.json` | 0600 | Client id, Agent URL, hash of the enrolment token, last revision, and per-grant state. |

If `agent.crt` is missing the agent is not enrolled. The agent enrols again whenever the configured token's hash differs from the one in `state.json`.

## Enrolment token

`cf1.<base64url(Agent URL)>.<CA SHA-256, 64 hex digits>.<secret>`. The Agent URL must be `https://host[:port]`. The agent checks the server's answer against the CA fingerprint in the token.

## Transport

`CF_AGENT_TRANSPORT` decides only which TLS certificate from the server is acceptable. Whatever the mode, the agent signs every request, encrypts every body, and verifies each response against the agent CA bundle.

| Mode | The TLS certificate must be |
|---|---|
| `auto` | Issued by an agent CA when the server presents such a chain (held to that CA, name included); otherwise trusted by the system roots (or `SSL_CERT_FILE`). |
| `mtls` | Issued by an agent CA. For the dedicated agent port only. |
| `proxy` | Trusted by the system roots (or `SSL_CERT_FILE`). For a TLS-terminating proxy. |

Enrolment accepts either a chain containing the token's CA or a system-trusted chain, whatever the mode. The agent presents no TLS client certificate in any mode; the server asks for none.

## Protocol limits

| Limit | Value |
|---|---|
| Clock difference accepted by the server | 60 seconds. Beyond it the agent reports that the system clocks differ. |
| Replay protection | Each nonce is remembered for 120 seconds, in the server's memory, in one cache shared by the HTTP port and the agent listener. A restart forgets them. At 200,000 remembered nonces the server answers an unsigned `503` with `Retry-After` and logs an error until entries expire. |
| Request rate | Session, WebSocket, poll and every signed request: 600 a minute per client address (burst 120), checked before the body is read or any signature verified. A request naming no live session is refused before its body is read. |
| Session lifetime | 10 minutes; the agent starts a new session after 9. |
| Sessions per client | 16. The oldest is dropped. |
| Messages per session | 1000 each way. The WebSocket reconnects shortly before the limit (close code 4003) for fresh keys. |
| WebSocket message size | 8 MiB. |
| Responder certificate | Valid 24 hours; the agent checks it on every response. |
| Pending enrolments | 50 per organization. |
| Enrolment poll interval | 2 to 30 seconds, doubling. The agent gives up after 10 failed polls in a row. |
| Server ping | Every 25 seconds; closes after 75 seconds without traffic. |

WebSocket close codes: 4000 a newer connection replaced this one, 4001 revoked or re-enrolled, 4002 idle, 4003 reconnect for fresh keys.

The protocol itself is described in [Architecture](../internals/architecture.md#agent-protocol); its threat model is [ADR 0020](../internals/adr/0020-agent-protocol-through-proxy.md).

## Hook environment

| Variable | Value |
|---|---|
| `CF_GRANT_ID` | The grant's id. |
| `CF_CERTIFICATE_NAME` | The certificate's name. |
| `CF_VERSION_ID` | The deployed version's id. |
| `CF_FINGERPRINT` | The version's fingerprint. |
| `CF_FILES` | Colon-separated paths of the files written. |
| `PATH`, `HOME`, `LANG`, `TZ`, `LC_*` | Copied from the agent's environment. |

No other variable of the agent is passed on.

## Capabilities

The agent tells the server what it can do. The client header lists them: `traefik` always, `hooks` when `CF_HOOK_ALLOW` is set, `http-01` when `CF_AGENT_HTTP01_LISTEN` is set, and `tls-alpn-01` when `CF_AGENT_TLSALPN_LISTEN` is set.

## See also

- [Agents](../guide/agents.md), [Clients](../guide/clients.md)
- [Configuration](configuration.md#agents): server-side agent settings.
