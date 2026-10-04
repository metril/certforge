# Deploy targets

A deploy target is what an agent does with a certificate besides writing layout files. Targets are defined per org under Delivery → Targets and chosen per grant. Each type publishes a JSON Schema at `GET /api/v1/meta/schemas` (`deployTargets`), and the UI builds its form from it. Shipped today:

| Type | Runs on | Key policy |
|---|---|---|
| `traefik` (Traefik) | agent | always |
| `vault-kv` (Vault KV) | server | optional |

The other seven vendor targets named in `docs/design.md`'s Phases table (Docker secrets, Kubernetes Secret, Proxmox VE, TrueNAS, OPNsense, UniFi, Home Assistant) are backlog — see Runs on and Key policy below for what those columns mean.

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

## Vault KV

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

The four `keys.*` field names must be distinct, and two files of a grant's layout may not land on one document field (a layout file whose base name equals a `keys.*` name collides too): the target config is 422 on the first, the grant create/update 422 on the second.

**Path collisions.** Two live server grants of one target may never render the same `(mount, path)`: the second would silently overwrite the first's document. `createServerGrant`, `updateServerGrant`, a certificate rename and a target edit that changes `mount` or `path` render the pair for every live grant of the target and answer 409 on a duplicate. Names that clean to the same string collide (`Web.One` and `web.one`), and a `path` with neither `{name}` nor `{cert}` allows exactly one grant per target.

**Org isolation.** The one shared Vault has no per-org mounts, so a principal without global `delivery:write` (an org-bound role or key) may only create or change a vault-kv target whose rendered path starts with the literal text `certforge/<its org slug>/` (`{org}` may stand for the slug; 403 otherwise). A global admin may use any path. A stored mount and path that a save leaves both unchanged are grandfathered, so an older target still saves.

Each deploy is one `PUT <mount>/data/<path>` (`internal/vault.Client.KVPut`), overwriting the whole document — nothing is merged with what was there before.

### Grants and status

A server-run target's grants are created and managed on the target itself, not from a client's grant editor: `POST`/`GET /orgs/{orgId}/deploy-targets/{id}/grants` (`clients:write`/`clients:read`; `includeKey` on the target additionally needs `keys:export`). A grant's `layoutId` is its only editable field afterwards (`PATCH /orgs/{orgId}/grants/{id}`); its layout must render PEM files only — a p12/jks/DER file is 422, since the whole point of a server grant is to avoid handing key material to anything but the target itself. Deleting a server grant removes it immediately: there is no agent to confirm files are gone, so there is no removal-pending state.

Deploy status lives in `serverDeployment` (`pending`, `deployed` or `failed`), in place of the agent-side `deployment` a client grant carries: `versionId` (the version deployed or being deployed), `lastError` (truncated to 1000 characters, and never containing a target's own secret — `targets.Redact` strips every stored secret value, its escaped forms, and its base64 form from a target's error before the dispatcher ever writes it, on top of whatever redaction the target implementation itself already applies, e.g. Vault tokens via `internal/vault.Client`), and `deployedAt`. Any server-run type deploys through this same shared dispatcher, driven by the target registry rather than a per-type switch — vault-kv today, any future server-run type without dispatcher changes. A new certificate version, `redeployGrant`, or an edited `layoutId` all mark the deployment `pending` and enqueue a fresh deploy (`certforge_server_deploy`, retried up to 5 times with river backoff); a grant with no version yet (a brand-new certificate not issued) stays `pending` with `versionId: null` until one exists. See [architecture.md](architecture.md#server-side-deploy) for the dispatcher itself.

## Runs on

Every deploy target type has a fixed `runsOn`, reported per type at `GET /api/v1/meta/schemas` (`deployTargets[].runsOn`): `server` (Vault KV — a client-less "server grant", above) or `agent` (Traefik — written by an enrolled agent, [agent.md](agent.md)). A type may instead be `either`, letting the operator pick per target at create time (`DeployTargetInput.runsOn`); no shipped type is `either` yet. Whichever way it is decided, a target's `runsOn` is fixed for its lifetime — `type` and `runsOn` are both immutable after create (422 on an attempted change), and a grant onto the target must match: a client grant needs an agent-run target, a server grant (`createServerGrant`) needs a server-run one.

## Key policy

Every deploy target type also has a fixed `keyPolicy`, reported alongside `runsOn`: `never` (the target's config can't need the private key at all), `always` (Traefik — a TLS certificate needs both a `certFile` and a `keyFile`), or `optional` (Vault KV — only when the target's own `includeKey` is set). `keyPolicy` decides whether a grant onto the target needs a key at all, and — for `optional` — whether `keys:export` must be held to create or keep it that way (Vault KV's own `includeKey` row, above, is the concrete example: the same rule generalizes to any future `optional` type).

## Secrets

A type's schema marks some of its config fields `"secret": true` (no shipped type has one yet; a future type — a webhook token, an API key — will). Those fields are write-only: `createDeployTarget`/`updateDeployTarget` accept them in `config`, but `getDeployTarget`/`listDeployTargets` never echo a value back — instead, `DeployTarget.storedSecrets` names which secret fields currently hold a value, so the UI can show "set" without showing what it is set to.

On update, a secret field left out of `config` entirely, or sent as the literal string `__unchanged__`, keeps whatever value is already stored; sending `__unchanged__` for a secret with no stored value is 422 ("`<field>` has no stored value"). An explicit empty string (`""`) clears it — allowed for an optional secret, 422 for one the type's own schema requires (the target simply can't validate without it). Changing a URL — the destination a secret authenticates against — while a secret is being kept unchanged is refused (422 "re-enter the secret"): a stored credential must never silently carry over to a new destination.

Every URL a type's config carries (`Config.URLs`, from its own `Parse`) is checked against the URL policy at create and update time: an agent-run target allows loopback and link-local addresses (the agent's own network is the operator's to reach), a server-run target only when the org's `allowLoopbackUrls` setting (Settings → Notifications) is on; the cloud-metadata addresses (`169.254.169.254`, `fd00:ec2::254`) are never allowed either way. A target whose resolved config needs the certificate's private key (`keyPolicy`, above) needs `keys:export` on every create and update, not only the first time it turns on.
