# Agents

`certforge-agent` runs on each host that needs certificates. It enrols once, keeps a connection to the server, writes the certificates granted to its client, runs allowlisted hooks, and reports what is installed so the server can detect drift. Create the client first: see [Clients](clients.md).

The agent talks to the server over HTTPS. Every request is signed and every body is encrypted by the agent protocol itself, so it also works through a reverse proxy that terminates TLS. The full list of variables and limits is in the [agent reference](../reference/agent.md).

## Before you start

- A client and its token, from [Clients](clients.md#enrolment).
- A persistent volume or directory for the agent's data (`CF_AGENT_DATA`, default `/data`). It holds the agent's key and certificate.
- Every directory the agent writes to must be mounted into the container and listed in `CF_WRITE_ALLOW`.

## Running with Docker

1. Run the agent with the token. Replace `<version>` with a release from the [Releases](https://github.com/metril/certforge/releases) page; pin it rather than using `:latest`.

   ```sh
   docker run -d --name certforge-agent --restart unless-stopped \
     -e CF_AGENT_TOKEN='<token>' \
     -e CF_WRITE_ALLOW=/etc/ssl/certforge \
     -v certforge-agent:/data \
     -v /etc/ssl/certforge:/etc/ssl/certforge \
     ghcr.io/metril/certforge-agent:<version>
   ```

2. Read the log for the verification code and approve the agent: [Clients: Approval](clients.md#approval).

To keep the token out of the environment, use Compose with a file secret. This example also shares a volume with Traefik so it picks up what the agent writes:

```yaml
services:
  certforge-agent:
    image: ghcr.io/metril/certforge-agent:<version>
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
```

The token is needed only until the agent has enrolled. After that the `/data` volume is its identity, so keep it. The image runs as root so layout owners and groups can be applied. With `--user`, the agent applies modes only, and `/data` must already be writable by that user: a fresh named volume is root-owned, so use a bind mount you have chowned, or chown the volume before the agent starts. For Traefik, see [Delivery](delivery.md#traefik).

### Install without Docker

Each release attaches static `certforge-agent_<version>_linux_<amd64|arm64>.tar.gz` files and `SHA256SUMS`.

```sh
curl -fsSLO https://github.com/metril/certforge/releases/download/<version>/certforge-agent_<version>_linux_amd64.tar.gz
curl -fsSLO https://github.com/metril/certforge/releases/download/<version>/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf certforge-agent_<version>_linux_amd64.tar.gz
sudo install -m 0755 certforge-agent /usr/local/bin/certforge-agent
```

The binary needs no libc. Run `certforge-agent run` under systemd, or `certforge-agent pull` from a timer (see [Pull mode](#pull-mode)). The commands are listed in the [agent reference](../reference/agent.md#commands).

## Behind a proxy

Use this when agents reach CertForge through a reverse proxy that terminates TLS (nginx, Caddy, Traefik, a cloud load balancer), instead of the dedicated agent port (8443). The proxy sees the agent's traffic but cannot read or change it: the agent signs each request and encrypts each body, and checks every answer against the agent CA. A proxy can still block traffic.

1. **Choose the public name.** For example `certforge.example.com`. The proxy needs a TLS certificate for it. Agents must trust that certificate (step 5).
2. **Point the proxy at the HTTP port.** Forward to the server's HTTP listener (`CF_LISTEN_HTTP`, default port 8080). That port serves `/agent/v1` as well as the UI. You do not need to publish the agent port (8443).
3. **Set the Agent URL.** In **Settings → Agents**, set **Agent URL** (`agents.agentUrl`) to the proxy's address with no path, for example `https://certforge.example.com`. Every new token carries this address. Agents that are already enrolled keep the address they enrolled with: re-enrol them to move them ([Clients](clients.md#re-enrol-a-client)). The host of **Agent URL**, or of `CF_BASE_URL`, must match the name agents use.
4. **Configure the proxy.** It must forward the `Host` header unchanged, allow WebSocket upgrades, pass the request and response headers untouched (the agent adds `Signature`, `Signature-Input`, `Content-Digest` and `Cf-*` headers), and accept request bodies of up to 8 MiB.

   nginx:

   ```nginx
   map $http_upgrade $connection_upgrade {
       default upgrade;
       ''      close;
   }

   server {
       listen 443 ssl;
       server_name certforge.example.com;
       ssl_certificate     /etc/ssl/certforge.example.com.crt;
       ssl_certificate_key /etc/ssl/certforge.example.com.key;

       client_max_body_size 10m;

       location / {
           proxy_pass http://certforge:8080;
           proxy_http_version 1.1;
           proxy_set_header Host $http_host;
           proxy_set_header X-Forwarded-For $remote_addr;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection $connection_upgrade;
           proxy_read_timeout 3600s;
           proxy_send_timeout 3600s;
       }
   }
   ```

   Caddy forwards `Host` unchanged and upgrades WebSockets without extra settings:

   ```caddy
   certforge.example.com {
       reverse_proxy certforge:8080
   }
   ```

   Use `$http_host` rather than `$host` in nginx so a non-default port stays in the header. Do not add path rewriting: the agent expects `/agent/v1/...` at the root of the name.

5. **Trust the proxy's certificate.** If it comes from a public CA, nothing more is needed. If it comes from a private CA, give the agent the CA certificate with `SSL_CERT_FILE`:

   ```sh
   docker run -d --name certforge-agent --restart unless-stopped \
     -e CF_AGENT_TOKEN='<token>' \
     -e SSL_CERT_FILE=/etc/ssl/proxy-ca.pem \
     -v /path/to/proxy-ca.pem:/etc/ssl/proxy-ca.pem:ro \
     -e CF_WRITE_ALLOW=/etc/ssl/certforge \
     -v certforge-agent:/data \
     -v /etc/ssl/certforge:/etc/ssl/certforge \
     ghcr.io/metril/certforge-agent:<version>
   ```

   `SSL_CERT_FILE` is read by the Go runtime and replaces the system CA list, so the file must contain every CA the agent should trust. It applies to enrolment and to later connections.
6. **Leave `CF_AGENT_TRANSPORT` unset.** It chooses which TLS certificates the agent accepts from the server: `auto` (the default) accepts the agent port's own certificate or, otherwise, a certificate trusted by the system roots; `proxy` accepts only system roots; `mtls` accepts only the agent port's certificate. Set `proxy` to refuse the agent port's certificate on purpose, and `mtls` when you never use a proxy. It does not change what is signed or encrypted. See the [agent reference](../reference/agent.md#transport).
7. **Check it.** Enrol a client. The agent log shows the verification code, and after approval the client shows **Online**. In the proxy's access log you should see requests to `/agent/v1/enroll/hello`, `/agent/v1/session` and `/agent/v1/assignments`.

To see the real source address in the **Approve agent** dialog and the audit log, add the proxy under **Trusted proxies** in **Settings → Authentication**. Proxy setups for the whole server are in [Deploying](../operations/deploying.md).

## File layouts

A layout (**Delivery → File layouts**) lists files by absolute path on the agent host. The agent writes each file atomically: a temporary file in the same directory, fsync, chmod, rename. Paths must be absolute and clean, and the directory must be mounted into the agent container and allowed by [`CF_WRITE_ALLOW`](#write-allowlist).

`owner` and `group` accept names or numeric ids and apply only when the agent runs as root; otherwise the agent logs one warning and applies the mode only. In the distroless image only `root`, `nonroot` (65532) and `nobody` resolve by name, so prefer numeric ids.

Each file has a format:

- **PEM** joins parts in order: `cert`, `chain`, `fullchain`, `key`, `combined` (fullchain and key), and `extra` (the leaf and chain of each extra certificate).
- **DER** holds exactly one part, `cert` or `key`.
- **PKCS#12** and **JKS** write one password-protected keystore with the certificate, chain, key and any extra certificates. They take no parts. PKCS#12 has an encoding, `modern` (default) or `legacy` for old consumers. JKS has an alias (default the file's base name) and needs a password of at least 6 characters.

A layout with a PKCS#12 or JKS file stores one export password, sealed like other secrets. It is never logged, returned by a read, or sent to an agent. Only the rendered bytes are. On update, send `__unchanged__` to keep it, or omit the field to clear it (clearing is refused while a keystore file still needs one).

A layout can bundle up to 10 other certificates from the same organization as extra certificates. Deleting a certificate that a layout still lists is refused until you remove it from the layout.

### Write allowlist

The agent writes or removes files only under directories listed in `CF_WRITE_ALLOW` (colon-separated absolute paths). Without it a compromised server could push a layout pointing anywhere on the host. With it empty, every deploy fails with a clear error and the agent logs a warning at startup. Set it to the directories you mount, for example `CF_WRITE_ALLOW=/etc/ssl:/etc/traefik/dynamic`. Symbolic links are resolved before the check, so a link cannot lead out of an allowed directory. `/` is rejected.

## Hooks and the allowlist

A hook is a command defined under **Delivery → Hooks** and attached to grants. The agent runs a hook only if its first argument (`argv[0]`) is exactly one of the paths in `CF_HOOK_ALLOW` (colon-separated). With it empty, hooks never run and are reported with exit code -1.

- Hooks run without a shell, so `$VAR`, `;` and `|` are literal.
- A **Pre-deploy** hook runs before files are written; a non-zero exit stops the deploy. A **Post-deploy** hook runs after; a non-zero exit marks the deployment failed with the files in place.
- Each hook gets `CF_GRANT_ID`, `CF_CERTIFICATE_NAME`, `CF_VERSION_ID`, `CF_FINGERPRINT` and `CF_FILES` (colon-separated paths), plus `PATH`, `HOME`, `LANG`, `TZ` and `LC_*` from the agent. Nothing else is passed on.
- A hook runs in its own process group and is killed with it at its timeout.
- Stdout and stderr are kept up to 8 KiB each and shown on the client's **Hooks** tab.
- The distroless image has no shell, libc or dynamic linker. A hook mounted into it must be a static binary (`CGO_ENABLED=0 go build`). A dynamic one fails to start with no useful error. Mount the executables you allow.

## Grants and reconcile

A grant gives one client one certificate, with a layout, a deploy target or both, plus hooks. Every change on the server (a new certificate version, an edit to a grant, layout, target or hook, a redeploy) raises the client's desired revision.

The agent reconciles when it connects, when the server nudges it, on its pull schedule, and on `certforge-agent pull`. It fetches the list of grants and downloads a bundle only for a grant whose certificate version, redeploy counter or file list changed. It installs what it downloaded and reports every grant. Files of grants the server no longer lists are removed first, then grants are installed; a path used by a live grant is never removed. The server refuses two grants on one client that would write the same path.

**Push** grants nudge the agent at once. A change that touches only **Pull** grants sends no nudge, so those wait for the agent's schedule. A failed deploy leaves no saved state for that grant, so the next reconcile starts it again from scratch.

A grant on a certificate with no version yet still appears, with only the files its target can render without a certificate (the Traefik ACME router file when `acmeServiceUrl` is set). See [Delivery](delivery.md#traefik).

## Drift

Each heartbeat (**Heartbeat interval (seconds)**, default 60) carries the SHA-256 of every installed file. This is the only place the server learns that a file changed on disk. A missing or changed file turns the deployment to **Drift** and records one `deployment.drift` audit event.

- Without auto-remediate, the deployment stays in **Drift** until you choose **Redeploy** on the grant.
- With **Auto-remediate** on the grant (under **Advanced** in the grant sheet), the server asks the agent to reinstall the files: at once for **Push**, on the next pull for **Pull**. The deployment returns to **Deployed** on the next report or heartbeat.
- **Redeploy** always reinstalls and re-runs the hooks, even when nothing changed.

## Pull mode

For hosts that should not keep a connection, run `certforge-agent pull` from cron or a systemd timer. It enrols if needed, renews its certificate when due, reconciles once, reports, sends one heartbeat and exits. Alternatively set `CF_AGENT_PULL_INTERVAL=15m` with `run` to reconcile on a schedule in addition to nudges. The schedule keeps working over plain requests while the connection is down, for example when a proxy refuses WebSocket upgrades.

Set a grant's **Delivery** to **Pull** for these hosts. If every grant is **Pull** and `CF_AGENT_PULL_INTERVAL` is `0`, deploys happen only when the agent reconnects or you run `pull`.

A pull-only agent does not receive live trust updates. After an agent CA rotation it gets the new CA bundle when it renews, and the old CA stays trusted until you retire it. See [Key management](../operations/key-management.md#agent-ca-rotation).

## Challenge serving

A verification rule with method `http-01` and **via: agent**, or with method `tls-alpn-01`, names a client. The server then asks that client's agent to answer the CA's challenge instead of answering it itself. See [Challenges](challenges.md) for the rule settings.

The agent reports its ability to serve each method when it connects, based on what is configured:

- **http-01 without a webroot.** Set `CF_AGENT_HTTP01_LISTEN` to a `host:port`, for example `:8080`. The agent answers `GET /.well-known/acme-challenge/<token>` there and returns 404 for everything else. Ports below 1024 need root or `CAP_NET_BIND_SERVICE`.
- **http-01 with a webroot.** The agent writes `<webroot>/.well-known/acme-challenge/<token>` (mode 0644) and removes it afterwards, so some other web server on the host can serve it. The webroot must be inside `CF_WRITE_ALLOW`. No listener is needed.
- **tls-alpn-01.** Set `CF_AGENT_TLSALPN_LISTEN` to a `host:port`, for example `:5001`. The agent serves a self-signed challenge certificate for the requested name, only to clients that ask for the `acme-tls/1` protocol.

The server waits up to 30 seconds for the agent to confirm. An issuance attempt fails with `client <name> is offline or cannot serve challenges` if the agent's connection is not open, `client <name> did not confirm the challenge within 30s` if it stays silent, or `client <name>: <error>` with the agent's own error. A rule's client is checked when the rule is saved: it must be in the same organization and report the method's capability, unless it is an http-01 rule with a webroot.

## Common problems

Server-side symptoms are in [Troubleshooting](../operations/troubleshooting.md).

**`enrol: 401 … invalid, already used or expired`.** Tokens work once and expire. Choose **Re-enrol** for a new one.

**`the server's responder chain does not contain the CA pinned by the token`.** The agent reached something that is not your CertForge server, or the CA named in the token has been retired. Check the **Agent URL**; if an agent CA was rotated and retired since the token was made, issue a new token.

**`the verification code from the server … does not match this agent's`.** The agent is not talking to the CA in its token. Do not approve; check the Agent URL and the network path.

**The log says `ENROLMENT WAITING FOR APPROVAL` and nothing happens.** An administrator must approve it. See [Clients: Approval](clients.md#approval). If the log then says the request was rejected or expired, get a new token.

**`x509: certificate signed by unknown authority` through a proxy.** The proxy's certificate comes from a private CA. Set `SSL_CERT_FILE` ([step 5](#behind-a-proxy)).

**`x509: certificate is valid for …, not …` on the agent port.** The Agent URL's host is not on the listener certificate. Set **Agent URL** or **Listener names** under **Settings → Agents**.

**`the system clocks differ by more than a minute`.** Signed requests are accepted only within 60 seconds of the server's clock. Fix time sync on the host (NTP).

**The agent logs `the server refused this agent` and exits.** The client was revoked or re-enrolled. Re-enrol and start the agent with the new token.

**The connection keeps dropping.** Behind a proxy, check that WebSocket upgrades and long read timeouts are allowed. The server pings every 25 seconds and closes after 75 seconds of silence. The agent also reconnects on purpose roughly every 1000 messages; this is normal. With upgrades blocked, use [Pull mode](#pull-mode).

**The agent keeps failing after a long outage.** Its certificate may have expired (it renews at two thirds of its life). Re-enrol.

**A deployment stays Pending.** The agent is offline, the grant is **Pull** and no pull has run, or the certificate has no issued version. `certforge-agent status` shows the revision the agent last applied.

**A deployment is Failed with a hook message.** Open the client's **Hooks** tab. `not listed in CF_HOOK_ALLOW` means the agent's allowlist lacks that executable.

**A deployment is in Drift.** A file changed or vanished on the host. Turn on **Auto-remediate** or choose **Redeploy**.

**`not running as root: layout owner and group are ignored`.** The agent runs with `--user`; only modes are applied.

**A grant stays removal-pending.** Its agent is gone for good. Delete the grant with **Remove without waiting for the agent**, or revoke the client, which drops all of its removal-pending grants.

## See also

- [Clients](clients.md): create, approve, re-enrol, revoke.
- [Agent reference](../reference/agent.md): variables, commands, transport, limits.
- [Delivery](delivery.md): grants, deploy targets, Traefik.
- [Deploying](../operations/deploying.md): reverse proxy for the server.
- [Architecture: agent protocol](../internals/architecture.md#agent-protocol).
