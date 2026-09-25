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

## File layouts

A layout (Delivery → Layouts) lists files by absolute path on the agent host. Each file concatenates PEM parts in order: `cert`, `chain`, `fullchain`, `key`, `combined` (fullchain + key). Files are written atomically (temp file in the same directory, fsync, chmod, rename). `owner` and `group` accept names or numeric ids and apply only when the agent runs as root; otherwise the agent logs one warning and applies the mode only. In the distroless image only `root`, `nonroot` (65532) and `nobody` resolve by name, so prefer numeric ids. Paths must be absolute and clean; mount the target directories into the agent container.

## Traefik integration

Share Traefik's file-provider directory with the agent and grant the certificate with a Traefik target (see [deploy-targets.md](deploy-targets.md#traefik)):

    services:
      traefik:
        image: traefik:v3.1
        command:
          - --providers.file.directory=/etc/traefik/dynamic
          - --providers.file.watch=true
        volumes:
          - traefik-dynamic:/etc/traefik/dynamic:ro
      certforge-agent:
        image: ghcr.io/metril/certforge-agent:latest
        environment:
          CF_AGENT_TOKEN_FILE: /run/secrets/cf_agent_token
        secrets: [cf_agent_token]
        volumes:
          - certforge-agent:/data
          - traefik-dynamic:/etc/traefik/dynamic
    volumes:
      traefik-dynamic:
      certforge-agent:
    secrets:
      cf_agent_token:
        file: ./cf_agent_token

Target config: `dir: /etc/traefik/dynamic` (same path in both containers, so `pathPrefix` stays empty). Renewals overwrite the same files and rewrite the YAML, which Traefik's watcher picks up. No Docker socket, no reload command.

## Hooks and the allowlist

Hooks are commands defined in CertForge (Delivery → Hooks) and attached to grants. An agent runs a hook only if its `argv[0]` is exactly one of the paths in `CF_HOOK_ALLOW` (colon-separated). With `CF_HOOK_ALLOW` empty, hooks never run and are reported with exit code -1. Hooks run without a shell: `argv` is passed as is, so `$VAR`, `;` and `|` are literal. `pre_deploy` hooks run before files are written and a non-zero exit stops the deploy; `post_deploy` hooks run after and a non-zero exit marks the deployment failed with the files in place. Each hook gets `CF_GRANT_ID`, `CF_CERTIFICATE_NAME`, `CF_VERSION_ID`, `CF_FINGERPRINT` and `CF_FILES` (colon-separated paths) in its environment, runs in its own process group, and is killed with that group at its timeout. Stdout and stderr are kept up to 8 KiB each and shown under the client's Hooks tab. The distroless image has no shell; mount the executables you allow.
