# Deploy targets

A deploy target is what an agent does with a certificate besides writing layout files. Targets are defined per org under Delivery → Targets and chosen per grant. Each type publishes a JSON Schema at `GET /api/v1/meta/schemas` (`deployTargets`), and the UI builds its form from it.

## Traefik

Runs on the agent. Traefik's [file provider](https://doc.traefik.io/traefik/providers/file/) watches a directory (`providers.file.directory=/etc/traefik/dynamic`, `providers.file.watch=true`) and reloads TLS certificates without a restart. Mount the same directory into the agent container and point the target at it. CertForge does not use Traefik's own ACME.

| Field | Default | Meaning |
|---|---|---|
| `dir` | – (required) | The directory as the agent sees it. |
| `pathPrefix` | same as `dir` | The directory as Traefik sees it, when the two containers mount it at different paths. Used in the YAML's `certFile`/`keyFile`. |
| `defaultCert` | false | Also serve this certificate when no SNI matches, via `tls.stores.<store>.defaultCertificate`. |
| `stores` | `["default"]` | Traefik TLS stores the certificate joins. |
| `acmeServiceUrl` | – (optional) | Absolute `http://` or `https://` URL of an agent's http-01 listener (see [agent.md#challenge-serving](agent.md#challenge-serving)). When set, also writes `certforge-acme-<name>.yml`, routing ACME traffic through Traefik. |

Per grant the agent writes, in this order and atomically (temp file, fsync, rename): `certs/<name>/fullchain.pem` (0644), `certs/<name>/privkey.pem` (0600), `certforge-<name>.yml` (0644), and, when `acmeServiceUrl` is set, `certforge-acme-<name>.yml` (0644). `<name>` is the certificate name lower-cased with anything but `a-z 0-9 . _ -` turned into `-`. On renewal the same paths are overwritten, and rewriting the YAML makes Traefik's watcher fire. Deleting the grant removes the files in reverse order, so Traefik never points at a missing file. All files count for drift.

The `certforge-acme-<name>.yml` router is unrelated to the certificate itself, so the agent renders and installs it even for a grant whose certificate has no version yet — a `method: http-01, via: agent` rule behind Traefik can then issue its very first certificate, since Pebble/Let's Encrypt reaches the agent's listener through this route before any certificate exists: the server lists such a grant's assignment with `versionId: null` and this one file, and the agent writes it straight from the assignment's target config, without ever fetching a bundle.

The router's rule matches `Host()` on the certificate's own names (every SAN of the certificate row, known even before it has a version), so it claims only requests for this certificate, not every host Traefik serves. Traefik v3's `Host()` takes exactly one argument, so a certificate with more than one name gets one `Host()` per name, OR'd together and parenthesized: `(Host(`a`) || Host(`b`)) && PathPrefix(...)`. A wildcard name (`*.example.com`) is left out of the rule entirely — Traefik v3 rejects a literal `Host(`*.example.com`)`, and no ACME challenge type validates a wildcard over http-01 anyway — so a certificate whose every name is a wildcard gets no router file at all. It carries no `entryPoints`, so it listens on whatever entrypoints Traefik's static config defines rather than assuming one is named `web` — see docs/PROGRESS.md's Known gap for what that does not pin down.

    http:
      routers:
        certforge-acme-web:
          rule: Host(`web.example.com`) && PathPrefix(`/.well-known/acme-challenge/`)
          service: certforge-acme-web
          priority: 1000
      services:
        certforge-acme-web:
          loadBalancer:
            servers:
              - url: "http://agent:8080"

Example YAML for `dir: /data/traefik`, `pathPrefix: /etc/traefik/dynamic`, `defaultCert: true`:

    tls:
      certificates:
        - certFile: "/etc/traefik/dynamic/certs/web/fullchain.pem"
          keyFile: "/etc/traefik/dynamic/certs/web/privkey.pem"
          stores:
            - "default"
      stores:
        "default":
          defaultCertificate:
            certFile: "/etc/traefik/dynamic/certs/web/fullchain.pem"
            keyFile: "/etc/traefik/dynamic/certs/web/privkey.pem"

Compose example: see [agent.md](agent.md#traefik-integration).
