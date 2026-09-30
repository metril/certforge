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
| `CF_WRITE_ALLOW` | empty (every deploy fails) | Colon-separated absolute directory prefixes the agent may write or remove files under. See [File layouts](#file-layouts). |
| `CF_AGENT_PULL_INTERVAL` | `0` | Also reconcile on this schedule (for example `15m`, at least `1m`), whether or not the WebSocket is up; while it is down, `run` pulls over REST. `0` means only on server nudges and at connect. Set it when any grant for this client uses `pull` delivery. |
| `CF_AGENT_HTTP01_LISTEN` | empty (http-01 off) | `host:port` for the agent's own http-01 listener, for example `:8080`. Empty disables it; a `method: http-01, via: agent` rule with no `webroot` then fails. See [Challenge serving](#challenge-serving). |
| `CF_AGENT_TLSALPN_LISTEN` | empty (tls-alpn-01 off) | `host:port` for the agent's tls-alpn-01 listener, for example `:5001`. Empty disables it; a `method: tls-alpn-01` rule naming this client then fails. See [Challenge serving](#challenge-serving). |

## Commands

| Command | What it does |
|---|---|
| `certforge-agent run` | Enrol if needed, connect, reconcile on every nudge, heartbeat, renew, reconnect with backoff. The container default. |
| `certforge-agent enroll --token <t>` | Enrol and exit. |
| `certforge-agent pull` | One reconcile over REST, report, heartbeat, exit. No socket. |
| `certforge-agent status` | Print client id, agent URL, certificate expiry and last revision. |
| `certforge-agent version` | Print the version. |

## File layouts

A layout (Delivery → Layouts) lists files by absolute path on the agent host. Files are written atomically (temp file in the same directory, fsync, chmod, rename). `owner` and `group` accept names or numeric ids and apply only when the agent runs as root; otherwise the agent logs one warning and applies the mode only. In the distroless image only `root`, `nonroot` (65532) and `nobody` resolve by name, so prefer numeric ids. Paths must be absolute and clean; mount the target directories into the agent container.

Each file picks a format:

- `pem` concatenates PEM parts in order: `cert`, `chain`, `fullchain`, `key`, `combined` (fullchain + key), `extra` (the leaf and chain of each extra certificate, in order).
- `der` holds exactly one DER-encoded part, `cert` or `key` (one layout file is one path, and `chain` is one file per certificate, so it stays download-only).
- `p12` and `jks` write one password-protected keystore holding the certificate, its chain, its key, and any extra certificates (as CA/trusted entries); they take no `parts`. `p12` accepts `encoding` (`modern`, the default, or `legacy` for old consumers); `jks` accepts `alias` (default the file's base name) and requires the layout password to be at least 6 characters.

**Password.** A layout with any `p12`/`jks` file stores one export password, sealed the same way other secrets are (never logged, audited, returned by a read, or sent to an agent — only the rendered bytes are). `passwordSet` on the layout says whether one is stored, never the value. On update, send `__unchanged__` to keep the stored password, or omit the field (or send `""`) to clear it — clearing it is a 422 while a `p12`/`jks` file still needs one.

**Extra certificates.** A layout can bundle up to 10 other certificates from the same org (each with a current version) alongside its own, rendered as the `extra` PEM part or as additional keystore entries. Deleting a certificate still listed by a layout is refused (409) until it is removed from that layout.

### Write allowlist

The agent only writes or removes files under a directory listed in `CF_WRITE_ALLOW` (colon-separated absolute prefixes). A compromised or misconfigured server could otherwise push a layout or target pointing anywhere on the host; with `CF_WRITE_ALLOW` empty every deploy fails at once, per grant, with a clear error, and the agent logs a startup warning. Set it to the same directories you mount into the container — for example `CF_WRITE_ALLOW=/etc/ssl:/etc/traefik/dynamic`. Each write is checked against the allowlist after resolving symlinks on the deepest existing parent directory, so a symlink cannot be used to point an allowed path outside the allowed directory.

## Challenge serving

A verification rule with `method: http-01, via: agent` or `method: tls-alpn-01` names a `clientId`: instead of this server answering the ACME challenge itself, the named client's agent does. Over the agent's WebSocket, the server sends `challenge_present{token, keyAuth, domain, method, webroot?}` when an issuance attempt needs the challenge served, and the agent replies `challenge_ready{token, error?}` once it has done so (or could not). The server sends `challenge_cleanup{token}` once the CA has validated (or the attempt has otherwise finished); the agent's cleanup is best-effort and the server does not wait for a reply. `method` is `http-01` or `tls-alpn-01`; `webroot`, when set, is an absolute path an http-01 rule wrote for the operator to serve some other way (a running web server on that host, for example) instead of the agent's own listener.

The server waits up to 30 seconds for `challenge_ready` after sending `challenge_present`; a client whose socket is not open, or whose agent never answers within that bound, fails the attempt with `client <name> is offline or cannot serve challenges` or `client <name> did not confirm the challenge within 30s` respectively, and an error the agent itself reports surfaces as `client <name>: <error>`. A rule's `clientId` is checked when the rule is saved (same org, and the client reports the method's capability, unless it is an http-01 rule with its own `webroot`), not only when an attempt runs.

Serving the challenge itself is the agent's own job, reported to the server as the `http-01`/`tls-alpn-01` capabilities in `hello` whenever the matching listener is configured:

- **http-01**, no `webroot`: `CF_AGENT_HTTP01_LISTEN` (`host:port`, for example `:8080`) binds a listener that answers `GET /.well-known/acme-challenge/<token>` with the key authorization, and 404s otherwise. It needs no root privilege for a port above 1024; a port below it needs `CAP_NET_BIND_SERVICE` or running as root.
- **http-01**, with `webroot`: the agent writes `<webroot>/.well-known/acme-challenge/<token>` (mode 0644) through the same confined, atomic writer as layout files, and removes it once the CA is done. `webroot` must resolve under [`CF_WRITE_ALLOW`](#write-allowlist), exactly like any layout or target path; a rule using an agent's webroot needs no `CF_AGENT_HTTP01_LISTEN`, since some other web server on that host serves the file.
- **tls-alpn-01**: `CF_AGENT_TLSALPN_LISTEN` (`host:port`, for example `:5001`) binds a TLS listener advertising only the `acme-tls/1` ALPN protocol; a handshake that does not request it is refused. For the domain named in `challenge_present`, it serves a self-signed certificate built with lego's `tlsalpn01.ChallengeCert`, looked up by the SNI the CA dials with.

A method the agent has no listener (and, for http-01, no webroot) for replies `challenge_ready` with an error, which the server reports as `client <name>: this agent has no <method> listener configured...`.

## Traefik integration

Traefik is a deploy target rendered from the shared registry (`internal/targets`), the same registry-driven path every agent-side (`runsOn: agent`) target type uses: the agent looks the grant's target type up in its own registry and renders it through the type's `Files`/`Reload`, never a hardcoded switch on "traefik". A client-less, server-run target (today, only Vault KV) is not run by an agent at all — an agent that somehow receives one refuses it outright, since API-driven targets are not run by agents yet.

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
          CF_WRITE_ALLOW: /etc/traefik/dynamic
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

Set `acmeServiceUrl` (an absolute `http://` or `https://` URL reaching this agent's [`CF_AGENT_HTTP01_LISTEN`](#challenge-serving)) to also route ACME traffic through Traefik: the target writes a per-grant `certforge-acme-<SafeName>.yml` forwarding `PathPrefix(`/.well-known/acme-challenge/`)` to that URL. It is rendered even before the grant's certificate has a first version, so a `method: http-01, via: agent` rule behind Traefik can issue its very first certificate; see [deploy-targets.md#traefik](deploy-targets.md#traefik).

## Hooks and the allowlist

Hooks are commands defined in CertForge (Delivery → Hooks) and attached to grants. An agent runs a hook only if its `argv[0]` is exactly one of the paths in `CF_HOOK_ALLOW` (colon-separated). With `CF_HOOK_ALLOW` empty, hooks never run and are reported with exit code -1. Hooks run without a shell: `argv` is passed as is, so `$VAR`, `;` and `|` are literal. `pre_deploy` hooks run before files are written and a non-zero exit stops the deploy; `post_deploy` hooks run after and a non-zero exit marks the deployment failed with the files in place. Each hook gets `CF_GRANT_ID`, `CF_CERTIFICATE_NAME`, `CF_VERSION_ID`, `CF_FINGERPRINT` and `CF_FILES` (colon-separated paths) in its environment, runs in its own process group, and is killed with that group at its timeout. Stdout and stderr are kept up to 8 KiB each and shown under the client's Hooks tab. The distroless image has no shell and no dynamic linker or libc at all, so a hook mounted into it must be a statically linked binary (`CGO_ENABLED=0 go build`, or any other toolchain's static output) — a dynamically linked one fails to start with no useful error. Mount the executables you allow.

## Grants and reconcile

A grant gives one client one certificate with a layout, a deploy target, or both, plus hooks. Every change on the server (new certificate version, grant edit, layout, target or hook edit, redeploy) raises the client's desired revision. The agent reconciles on connect, on every `sync` nudge, on its pull schedule, and on `certforge-agent pull`: it fetches all assignments and downloads a bundle only for grants whose assignment changed — its certificate version, its `redeploySeq` (bumped by an explicit Redeploy or by server-side auto-remediation), or its rendered file list — never for one whose on-disk bytes merely look wrong; that is what a heartbeat is for (see [Drift](#drift)). It installs what it downloads and reports every grant. Files of grants the server no longer lists are removed first (Traefik YAML first), then grants are installed; a path that a live grant lists is never removed. The server refuses two grants on one client that would write the same path. `push` grants nudge the agent immediately; a change that touches only `pull` grants sends no nudge, so they wait for the agent's own schedule (or the next nudge for another grant). A failed deploy leaves the agent with no saved state for that grant, so the next reconcile retries it from scratch rather than trusting whatever was partially written.

A grant on a certificate with no version yet still appears in the assignment list, with `versionId: null` and its target's material-independent files only (today, the Traefik ACME router file when `acmeServiceUrl` is set, see [deploy-targets.md#traefik](deploy-targets.md#traefik)); the agent installs those straight from the assignment's target config and never fetches a bundle for it, since the bundle endpoint has nothing to serve before a version exists.

## Drift

Every heartbeat (Settings → Agents, 60 s by default) carries the SHA-256 of each installed file; this is the only place an on-disk mismatch is ever detected — the reconcile loop above never reads the files it already installed back off disk. A missing or changed file turns the deployment to `drift` and records one `deployment.drift` audit event. Without auto-remediate the deployment simply stays `drift` until an operator calls Redeploy; nothing about reconciling on its own clears it, since the assignment itself has not changed. With auto-remediate on the grant, the server bumps the grant's `redeploySeq` (this is what actually forces a redeploy: the version and rendered files are otherwise unchanged) and raises the revision, so the agent reinstalls the files: right away for a `push` grant, on the next pull for a `pull` grant; the deployment returns to `ok` on the next report or heartbeat. Redeploy (client detail → grant → Redeploy) does the same `redeploySeq` bump unconditionally — it force-reinstalls a grant that already looks `ok`, rewriting every file and re-running its hooks, whether or not anything actually changed.

## Pull mode

For hosts that should not hold a socket, run `certforge-agent pull` from cron or a systemd timer: it enrols if needed, renews its certificate when due, reconciles once over REST, reports, sends one heartbeat and exits. Alternatively set `CF_AGENT_PULL_INTERVAL=15m` with `run` to reconcile on a schedule in addition to nudges; the schedule keeps running over REST while the WebSocket is down (for example behind a proxy that refuses upgrades).

A pull-mode agent never receives `trust_bundle_update`. After an agent CA rotation it picks up the new bundle when it renews (the renew response carries it), and the listener keeps the old CA until that CA is retired, so it keeps working meanwhile; see operations.md → Agent CA rotation.

## Running with Docker

One command, with the token from Clients → Enrol client:

    docker run -d --name certforge-agent --restart unless-stopped \
      -e CF_AGENT_TOKEN='<token>' \
      -e CF_WRITE_ALLOW=/etc/ssl/certforge \
      -v certforge-agent:/data \
      -v /etc/ssl/certforge:/etc/ssl/certforge \
      ghcr.io/metril/certforge-agent:latest

Compose, keeping the token out of the environment, with a Traefik service sharing the deploy target's volume so it actually picks up what the agent writes:

    services:
      certforge-agent:
        image: ghcr.io/metril/certforge-agent:latest
        restart: unless-stopped
        environment:
          CF_AGENT_TOKEN_FILE: /run/secrets/cf_agent_token
          CF_WRITE_ALLOW: /etc/traefik/dynamic
          # CF_HOOK_ALLOW: /hooks/reload-nginx
        secrets: [cf_agent_token]
        volumes:
          - certforge-agent:/data
          - traefik-dynamic:/etc/traefik/dynamic
      traefik:
        image: traefik:v3
        command: --providers.file.directory=/etc/traefik/dynamic --providers.file.watch=true
        volumes:
          - traefik-dynamic:/etc/traefik/dynamic:ro
        ports: ["443:443"]
    volumes:
      certforge-agent:
      traefik-dynamic:
    secrets:
      cf_agent_token:
        file: ./cf_agent_token

Mount every directory a layout or target writes to, and list it in `CF_WRITE_ALLOW` (see [Write allowlist](#write-allowlist)) — without it every deploy fails. The image runs as root so layout owners and groups can be applied; with `--user` the agent applies modes only, and `/data` must already be writable by that user — a plain named volume like `certforge-agent:` above is created root-owned on first use, so a non-root `--user` needs either a bind mount you have chowned yourself, or an init step that chowns the volume before the agent starts. The token is needed only until the agent has enrolled; after that the `/data` volume is its identity, so keep it.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `enrol: 401 … invalid, already used or expired` | Tokens are single-use and expire (24 h by default). Re-enrol the client for a new token. |
| `enrol: 409 … no longer signs the listener certificate` | The CA the token pins was retired after the token was created. Re-enrol the client for a new token. |
| `… does not contain the CA pinned by the token` | Something between the agent and the server terminates TLS, or the Agent URL points at the wrong service. The agent port needs TLS passthrough. |
| `x509: certificate is valid for …, not …` after enrolment | The Agent URL host is not on the listener certificate. Set Settings → Agents → Agent URL (its host is added automatically) or Listener names. |
| Agent logs `the server refused this agent` and exits | The client was revoked or re-enrolled, or its certificate was replaced. Re-enrol and restart the agent with the new token. |
| Agent keeps reconnecting after a long outage | Its certificate expired (it renews at two thirds of the lifetime). Re-enrol. |
| Deployment stays `pending` | The agent is offline, the grant is `pull` and no pull ran yet, or the certificate has no issued version. `certforge-agent status` shows the last revision it applied. |
| Deployment `failed` with a hook message | See the client's Hooks tab. `not listed in CF_HOOK_ALLOW` means the agent's allowlist lacks that executable. |
| Deployment in `drift` | A file changed or vanished on the host. Turn on auto-remediate or use Redeploy. |
| `not running as root: layout owner and group are ignored` | The agent runs with `--user`; only modes are applied. |
| A grant stays removal-pending forever | Its agent is gone for good and will never report the files removed. `DELETE .../grants/{id}?force=true` hard-deletes it at once; revoking the client does this automatically for all of its removal-pending grants. |
