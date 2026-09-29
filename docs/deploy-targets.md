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

## Vault KV {#vault-kv}

Runs on the server, not an agent — its grants are client-less ("server grants") and have no client to enroll or check in. Writes a certificate's rendered files as one document in a Vault (or OpenBao) [KV v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2) secrets engine. Settings → Integrations → Vault must be configured first (see [vault.md](vault.md#integrations)); every write uses that section's token/AppRole, never a credential stored on the target itself.

| Field | Default | Meaning |
|---|---|---|
| `mount` | `secret` | KV v2 secrets engine mount path. |
| `path` | `certforge/{org}/{name}` | Secret path within the mount. May use `{org}` (the org's slug), `{cert}` (the certificate's id) and `{name}` (the certificate's name, cleaned the same way Traefik's `<name>` is); no other `{…}` placeholder is allowed. The rendered path must not start with `/` or contain `..`. |
| `keys.fullchain` | `fullchain.pem` | Document field the full chain PEM is written under. |
| `keys.cert` | `cert.pem` | Document field the leaf certificate PEM is written under. |
| `keys.chain` | `chain.pem` | Document field the intermediate chain PEM is written under. |
| `keys.key` | `privkey.pem` | Document field the private key PEM is written under, when `includeKey` is set. |
| `includeKey` | `false` | Also write the private key. `keys:export` is checked wherever this can end up true: setting or keeping it on the target itself (`createDeployTarget`/`updateDeployTarget`), and creating or updating a grant onto a target that has it set (`createServerGrant`/`updateServerGrant`). A grant's own layout may not render a key without it either — a PEM layout file with a `key`/`combined` part is 422 on a target without `includeKey`, not silently dropped. |

Without a layout, the document gets exactly `keys.fullchain`/`keys.cert`/`keys.chain` (plus `keys.key` when `includeKey`). With a layout, each of the layout's own output files is written under its own file name instead (e.g. an `/etc/ssl/web.pem` file lands at the `web.pem` field); a server grant's layout may only render PEM files (see Grants and status below), and among those a `key`/`combined` part is refused outright (422, not silently dropped) unless the target has `includeKey`.

Each deploy is one `PUT <mount>/data/<path>` (`internal/vault.Client.KVPut`), overwriting the whole document — nothing is merged with what was there before.

### Grants and status

A server-run target's grants are created and managed on the target itself, not from a client's grant editor: `POST`/`GET /orgs/{orgId}/deploy-targets/{id}/grants` (`clients:write`/`clients:read`; `includeKey` on the target additionally needs `keys:export`). A grant's `layoutId` is its only editable field afterwards (`PATCH /orgs/{orgId}/grants/{id}`); its layout must render PEM files only — a p12/jks/DER file is 422, since the whole point of a server grant is to avoid handing key material to anything but the target itself. Deleting a server grant removes it immediately: there is no agent to confirm files are gone, so there is no removal-pending state.

Deploy status lives in `serverDeployment` (`pending`, `deployed` or `failed`), in place of the agent-side `deployment` a client grant carries: `versionId` (the version deployed or being deployed), `lastError` (truncated to 1000 characters, and never containing a Vault token or AppRole secretId — every `internal/vault.Client` error is redacted before a `Target` implementation ever returns it), and `deployedAt`. A new certificate version, `redeployGrant`, or an edited `layoutId` all mark the deployment `pending` and enqueue a fresh deploy (`certforge_server_deploy`, retried up to 5 times with backoff); a grant with no version yet (a brand-new certificate not issued) stays `pending` with `versionId: null` until one exists. See [architecture.md](architecture.md#server-side-deploy) for the dispatcher itself.
