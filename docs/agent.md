# certforge-agent

certforge-agent runs on each host that needs certificates. It enrols once with a one-time token, then keeps a mutual-TLS WebSocket to the server's agent listener, installs the certificates granted to it, runs allowlisted hooks, and reports what is installed so the server can detect drift.

## Enrolment

1. In CertForge, Clients → Enrol client. Pick a name and optionally a site. You get a token `cf1.<agent URL>.<CA fingerprint>.<secret>`, valid for 24 hours by default (Settings → Agents) and shown once.
2. Start the agent with the token (`CF_AGENT_TOKEN`, `CF_AGENT_TOKEN_FILE`, or `certforge-agent enroll --token …`).
3. The agent creates `agent.key` (ECDSA P-256, 0600) in its data directory, sends a CSR, and accepts the server only if the server's certificate chain contains the CA whose SHA-256 is in the token. It stores `agent.crt`, the CA bundle `ca.pem` and `state.json`. The client turns active.

The agent renews its certificate at two thirds of its lifetime (90 days by default). An expired certificate cannot be renewed: re-enrol the client (Clients → client → Settings → Re-enrol) and give the agent the new token; changing `CF_AGENT_TOKEN` and restarting is enough, since the agent re-enrols whenever the configured token differs from the one it enrolled with. The data directory must persist across restarts.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `CF_AGENT_DATA` | `/data` | Data directory (key, certificate, CA bundle, state). Mode 0700. |
| `CF_AGENT_TOKEN` | – | Enrolment token. |
| `CF_AGENT_TOKEN_FILE` | – | File holding the token, for example a Docker secret. Used when `CF_AGENT_TOKEN` is empty; `run` waits for it to appear. |
| `CF_HOOK_ALLOW` | empty (hooks off) | Colon-separated absolute paths of executables hooks may run. See [Hooks and the allowlist](#hooks-and-the-allowlist). |
| `CF_AGENT_PULL_INTERVAL` | `0` | Also reconcile on this schedule (for example `15m`, at least `1m`), whether or not the WebSocket is up; while it is down, `run` pulls over REST. `0` means only on server nudges and at connect. Set it when any grant for this client uses `pull` delivery. |

## Commands

| Command | What it does |
|---|---|
| `certforge-agent run` | Enrol if needed, connect, reconcile on every nudge, heartbeat, renew, reconnect with backoff. The container default. |
| `certforge-agent enroll --token <t>` | Enrol and exit. |
| `certforge-agent pull` | One reconcile over REST, report, heartbeat, exit. No socket. |
| `certforge-agent status` | Print client id, agent URL, certificate expiry and last revision. |
| `certforge-agent version` | Print the version. |
