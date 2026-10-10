# Deploying

CertForge is one server process plus Postgres. This page covers the compose files, the ports and the reverse proxy in front. Run one server replica: the agent hub, agent sessions and request nonces live in process memory.

## Before you start
- Docker with Compose, or a way to run the `certforge` binary against Postgres 16.
- An encryption key (KEK). Create it as in [Getting started](../guide/getting-started.md) and keep a copy outside the server. See [the encryption key](../reference/configuration.md#the-encryption-key).
- A DNS name for CertForge and a TLS certificate for the proxy in front of it. For a first test you can skip the proxy.

## Choose a compose file
Both files live in `deploy/` and start Postgres and the server with the same variables, ports and secret.

| File | What it runs |
|---|---|
| `deploy/compose.yaml` | Builds the server image from the checkout. |
| `deploy/compose.release.yaml` | Pulls `ghcr.io/metril/certforge:${CF_VERSION:-latest}`. Pin `CF_VERSION` in production. |

Start a release:

```sh
CF_VERSION=0.8.0 docker compose -f deploy/compose.release.yaml up -d
```

Variables the compose files read from your shell:

| Variable | What it does | Default |
|---|---|---|
| `CF_DB_PASSWORD` | Postgres password, also used in `CF_DATABASE_URL`. | `certforge` |
| `CF_BASE_URL` | Public URL of the web UI and API. | `http://localhost:${CF_HTTP_PORT}` |
| `CF_HTTP_PORT` | Host port for the HTTP listener. | `8080` |
| `CF_AGENT_PORT` | Host port for the agent listener. | `8443` |
| `CF_LOG_LEVEL` | Log level. | `info` |
| `CF_VERSION` | Image tag (release file only). | `latest` |

The server reads the KEK from the secret file `deploy/secrets/kek`. All other server variables are in [Configuration](../reference/configuration.md). Compose sets `stop_grace_period: 60s`; see [Shutdown](#shutdown).

## Ports and listeners
| Listener | Variable | Default | Serves |
|---|---|---|---|
| HTTP | `CF_LISTEN_HTTP` | `:8080` | Web UI, `/api/v1`, `/healthz`, `/readyz`, `/metrics`, `/.well-known/acme-challenge/`, and the agent protocol under `/agent/v1`. |
| Agent | `CF_LISTEN_AGENT` | `:8443` | `/agent/v1` only, over TLS. |

The agent protocol is signed and sealed by the application, so it works on either port and through a proxy that terminates TLS. Agents need only one of the two:
- **Through a proxy (recommended):** agents use the same URL as browsers. Publishing port 8443 is optional; remove the `ports` line if you do not use it.
- **Direct:** agents connect to port 8443. The listener presents a certificate from the internal agent CA for the names in **Settings → Agents → Listener names** plus the **Agent URL** host. It asks for no client certificate and speaks HTTP/1.1 only. The server renews the certificate hourly and when two thirds of its life has passed. If it cannot be issued at startup, the agent listener does not start. Fix the cause and restart.

The server also runs a short-lived responder certificate (24 hours) that signs every agent response. You do not manage it. See [Security model](security-model.md#agent-channel).

## Put a reverse proxy in front
Terminate TLS at the proxy and forward to `certforge:8080`. Three things matter for agents:
1. Forward the `Host` header unchanged. Agents sign the host they dial, and the server accepts only the **Agent URL** host (and, on the HTTP port, the `CF_BASE_URL` host).
2. Allow WebSocket upgrades.
3. Do not strip or rewrite the `Signature`, `Signature-Input`, `Content-Digest` and `Cf-*` headers, or change request and response bodies.

Then set **Settings → Agents → Agent URL** to the proxy URL, for example `https://certforge.example.com`. Enrolment tokens carry that URL.

**Caddy**

```caddyfile
certforge.example.com {
	reverse_proxy certforge:8080
}
```

Caddy forwards `Host` and upgrades by default.

**nginx**

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl;
    server_name certforge.example.com;
    # ssl_certificate / ssl_certificate_key ...
    client_max_body_size 10m;

    location / {
        proxy_pass http://certforge:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

**Traefik** (file provider)

```yaml
http:
  routers:
    certforge:
      rule: Host(`certforge.example.com`)
      entryPoints: [websecure]
      tls: {}
      service: certforge
  services:
    certforge:
      loadBalancer:
        servers:
          - url: http://certforge:8080
```

Traefik forwards `Host` and WebSockets by default.

To record real client addresses in the audit log and rate limiters, add the proxy to **Settings → Authentication → Trusted proxies**. See [Security model](security-model.md#client-addresses).

## Route HTTP-01 challenges
A `http-01` rule with `via: server` is answered by CertForge at `GET /.well-known/acme-challenge/{token}` on the HTTP listener. The CA connects to each certificate name on port 80, so route that path to CertForge from whatever answers port 80 for those names. With nginx:

```nginx
location /.well-known/acme-challenge/ {
    proxy_pass http://certforge:8080;
}
```

A name with nothing listening on port 80 fails that rule's challenge. See [Challenges](../guide/challenges.md#http-01).

## Run the binary directly
`certforge serve` applies migrations, checks the encryption key and starts the listeners. Subcommands are in [Server CLI](../reference/server-cli.md). Background work (issuance scans, renewals, sweeps) runs inside the same process. A scan every 5 minutes enqueues one job per certificate due for issuance or renewal, marks expired certificates, and closes attempts left running for over 4 hours.

## Shutdown
On SIGINT or SIGTERM the server drains in order:
1. The agent listener and the HTTP server stop accepting connections and give in-flight requests up to 15 s.
2. The job queue stops fetching jobs and gives running ones up to 30 s.
3. Jobs still running are cancelled and get 10 s more. A cancelled issuance is recorded as failed and retried with the usual backoff.

That is about 55 s, so your stop timeout must allow at least that. Compose sets 60 s. On Kubernetes set `terminationGracePeriodSeconds: 60`.

## Request limits
These protect public routes (`/auth/login`, `/setup/complete`) and agents from resource exhaustion.

| Limit | Value |
|---|---|
| Request body under `/api/v1` | 1 MiB (`413`). Certificate import accepts 32 MiB. |
| Password length | 1024 bytes (`422`). |
| Concurrent password hashes | 4, server-wide (`503` with `Retry-After: 1`). |
| Server timeouts | Header read 10 s, request read 30 s, idle 120 s. |
| Login, OIDC and setup | Per client address, set in **Settings → Authentication**. |
| Agent enrolment (`hello` and `enroll`) | Per client address, same defaults as login. |
| Agent sessions, polls and sockets | 600 per minute per client address, burst 120. |
| Agent message size | 8 MiB per WebSocket message. |

Agents must keep their clock within 60 s of the server's. See [Troubleshooting](troubleshooting.md#agents).

## Common problems
**Agents cannot connect through the proxy.** The proxy changed `Host`, blocked the upgrade, or dropped a signature header. Check the agent log for `stale`, `auth` or `session` errors and compare the host in **Agent URL** with the host your proxy forwards.

**Port 8080 or 8443 is already in use.** Set `CF_HTTP_PORT` or `CF_AGENT_PORT` before `docker compose up`.

**The server restarts mid-issuance on deploy.** The stop timeout is shorter than the drain time. Set 60 s or more.

**Agent listener is not running.** The log says `agent listener certificate not issued`. Set **Listener names** or **Agent URL**, then restart.

## See also
- [Upgrades](upgrades.md), [Monitoring](monitoring.md), [Security model](security-model.md)
- [Behind a proxy (agent side)](../guide/agents.md#behind-a-proxy)
- [Configuration](../reference/configuration.md)
