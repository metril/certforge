# Delivery

Delivery is how a certificate reaches the place that uses it. A **deploy target** says what to do with a certificate besides writing files, such as updating Traefik or storing the files in Vault. A **grant** links one certificate to one target or client. Open **Delivery** in the sidebar to manage targets, file layouts and hooks.

Two target types ship with CertForge:

| Type | Runs on | Private key |
|---|---|---|
| Traefik (`traefik`) | An agent | Always sent |
| Vault KV (`vault-kv`) | The server | Only if you switch on **Include private key** |

## Before you start

- You need the `delivery:write` permission to add or edit targets. Viewers can open a target read-only.
- Delivery belongs to one org, so it is not offered under **All orgs**.
- A Traefik target needs an enrolled agent. See [Clients](clients.md) and [Agents](agents.md).
- A Vault KV target needs Vault configured first. See [Vault](vault.md#integrations).

## Add a deploy target

1. Open **Delivery → Deploy targets** and select **Add target**.
2. Enter a **Name**.
3. Pick a **Type**. Each choice carries a chip for where it runs.
4. Fill in the **Settings** the type shows. The fields are listed under [Traefik](#traefik) and [Vault KV](#vault-kv).
5. Select **Save**.

The list shows each target as its name over a muted line: the type, where it writes (a directory, path or URL), and "secrets stored" if it holds any. The **Runs on** column shows Server or Agent. **Used by** shows how many grants use it.

To change a target, select the pencil on its row. To delete one, select the bin and type its name. A target that grants still use cannot be deleted. Remove those grants first.

## Runs on

Every type runs in one place, and that place is fixed once the target exists.

- **Server**: CertForge pushes each new version itself. No client is involved.
- **Agent**: an enrolled agent on the host writes the files.

**Runs on** is locked after you create the target, and so is **Type**. To change either, create a new target. A type that supports both modes lets you pick **Server** or **Agent** when you add the target. Neither shipped type does, so the control is fixed for both.

A client grant needs an agent target. A server grant needs a server target.

## Traefik

A Traefik target writes certificates where Traefik's [file provider](https://doc.traefik.io/traefik/providers/file/) watches. Traefik reloads them without a restart. CertForge does not use Traefik's own ACME. Start Traefik with `providers.file.directory` set and `providers.file.watch=true`, and mount that directory into the agent container.

| Field | What it does | Default |
|---|---|---|
| **Directory on the agent** (`dir`) | Traefik's file-provider directory as the agent sees it. Must be an absolute path. | Required |
| **Directory as Traefik sees it** (`pathPrefix`) | The same directory as Traefik sees it, when the two containers mount it at different paths. Used for `certFile` and `keyFile` in the YAML. | Same as the directory |
| **TLS stores** (`stores`) | Traefik TLS stores the certificate joins. Each is 1 to 64 letters, digits, `-` or `_`. | `default` |
| **ACME service URL** (`acmeServiceUrl`) | An absolute `http://` or `https://` URL of the agent's http-01 listener. Also routes ACME challenges through Traefik. See [Agents](agents.md#challenge-serving). | Empty |

For each grant the agent writes these files, each atomically:

1. `<certsDir>/fullchain.pem` (mode 0644)
2. `<certsDir>/privkey.pem` (mode 0600)
3. `certforge-<name>.yml` (mode 0644)
4. `certforge-acme-<name>.yml` (mode 0644), only when **ACME service URL** is set

`<certsDir>` is the grant's **Certificate directory on the agent**, `<dir>/certs/<name>` by default. `<name>` is the certificate name in lower case, with every run of other characters turned into `-`. On renewal the same paths are overwritten, and rewriting the YAML makes Traefik reload. Removing the grant deletes the files in reverse order, so Traefik never points at a missing file.

### Per-grant options

Each grant on a Traefik target has its own **Target options**, shown under the target picker in the grant sheet. The server validates them against the target type's grant schema (`grantSchema` in `GET /meta/schemas`).

| Field | What it does | Default |
|---|---|---|
| **Default certificate** (`defaultCert`) | Also serve this certificate when no SNI matches. Only one grant per client, directory and store may set it, otherwise the save fails with 409. | Off |
| **Certificate directory on the agent** (`certsDir`) | Absolute directory for `fullchain.pem` and `privkey.pem`. Must not equal the target's **Directory on the agent**. | `<dir>/certs/<name>` |
| **Certificate directory as Traefik sees it** (`certsDirTraefik`) | The same directory as Traefik sees it. | Derived from `dir` and `pathPrefix` when `certsDir` is under `dir`, else the same as `certsDir` |
| **TLS stores** (`stores`) | Overrides the target's stores for this certificate. | The target's |

On upgrade, a target's Default certificate moves to one grant per client: the certificate whose name sorts first, which is what Traefik was serving. Change it in the grant if another certificate should be the default.

The target no longer has a `defaultCert` field. Migration 00026 moved it onto the grants of each target that had it on. Agents older than this change ignore the options and report drift until you upgrade them. Upgrade the server first: a new agent fails to parse a stale target-level `defaultCert` from an old server.

Example YAML for `dir: /data/traefik`, `pathPrefix: /etc/traefik/dynamic` and **Default certificate** on for the grant:

```yaml
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
```

### Route ACME challenges through Traefik

Set **ACME service URL** so a rule that proves names over http-01 through an agent can work behind Traefik. The agent then writes `certforge-acme-<name>.yml`. It routes `/.well-known/acme-challenge/` for the certificate's names to the agent. The agent writes this file even before the certificate has its first version, so the very first issuance works.

- The rule lists one `Host()` per name of the certificate. Wildcard names are left out. A certificate whose names are all wildcards gets no such file.
- The router sets no `entryPoints`, so it listens on every entrypoint in Traefik's static config.

```yaml
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
```

### Run Traefik and the agent together

Share the directory between both containers. Use the same path in both, so **Directory as Traefik sees it** stays empty.

```yaml
services:
  traefik:
    image: traefik:v3.1
    command:
      - --providers.file.directory=/etc/traefik/dynamic
      - --providers.file.watch=true
    volumes:
      - traefik-dynamic:/etc/traefik/dynamic:ro
  certforge-agent:
    image: ghcr.io/metril/certforge-agent:<version>
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
```

Set **Directory on the agent** to `/etc/traefik/dynamic`. No Docker socket and no reload command are needed. Pin the agent image to a release version so an agent upgrade is a choice. The agent also needs a token and a server URL. See [Agents](agents.md#running-with-docker) and [the agent reference](../reference/agent.md).

### Replacing traefik-cert-watcher

Move to CertForge without serving a gap. Mount one directory in both containers, for example `/opt/docker/certs:/certs`:

```yaml
services:
  traefik:
    command:
      - --providers.file.directory=/certs
      - --providers.file.watch=true
    volumes:
      - /opt/docker/certs:/certs:ro
  certforge-agent:
    environment:
      CF_WRITE_ALLOW: /certs
    volumes:
      - /opt/docker/certs:/certs
```

1. Enrol the agent. See [Clients](clients.md).
2. Create a Traefik target with `dir: /certs` and an empty `pathPrefix`.
3. Grant each certificate to the target. Turn **Default certificate** on for exactly one. Set **Certificate directory on the agent** only when a certificate must keep a legacy location.
4. Confirm `certforge-*.yml` files appear in `/certs` and Traefik serves the certificates.
5. Stop traefik-cert-watcher.
6. Delete its `tls.yaml` and the legacy `<name>.crt` and `<name>.key` files.

While both run, `certforge-*.yml` sorts before `tls.yaml`, so CertForge's default certificate wins. Duplicate certificate entries only log warnings in Traefik.

## Vault KV

A Vault KV target stores a certificate's files as one document in a [KV v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2) secrets engine on Vault or OpenBao. It runs on the server, so its grants have no client. Configure **Settings → Integrations → Vault** first. See [Vault](vault.md#integrations). Every write uses that connection. The target holds no credential of its own.

| Field | What it does | Default |
|---|---|---|
| **Mount** (`mount`) | KV v2 mount path. | `secret` |
| **Path** (`path`) | Secret path inside the mount. May use `{org}` (the org slug), `{cert}` (the certificate id) and `{name}` (the certificate name). No other placeholder is allowed. The rendered path cannot start with `/` or contain `..`. | `certforge/{org}/{name}` |
| **Fullchain field** (`keys.fullchain`) | Document field for the full chain. | `fullchain.pem` |
| **Certificate field** (`keys.cert`) | Document field for the leaf. | `cert.pem` |
| **Chain field** (`keys.chain`) | Document field for the intermediates. | `chain.pem` |
| **Private key field** (`keys.key`) | Document field for the private key. Used only with **Include private key**. | `privkey.pem` |
| **Include private key** (`includeKey`) | Also write the private key. Needs the `keys:export` permission. | Off |

The four field names must be different from each other.

Each deploy replaces the whole document at `<mount>/data/<path>`. Nothing is merged with what was there. With a layout on the grant, each of the layout's files is written under its own file name instead. A server grant can use PEM layouts only. A layout part of `key` or `combined` is refused unless **Include private key** is on.

**Two grants cannot share one path.** If two grants of a target would render the same mount and path, the second is refused. Names that clean to the same string collide, such as `Web.One` and `web.one`. A path with neither `{name}` nor `{cert}` allows one grant per target.

**Org isolation.** One Vault serves every org. Without the global `delivery:write` permission, you can only use a path that starts with `certforge/<your org slug>/`, and **Mount** must be a single segment with no `/`. A global admin can use any path.

## Grant a certificate to a server target

A server target has no client, so you grant from the target.

1. On **Deploy targets**, select the **Grants** action (the paper-plane icon) on the target's row.
2. In the target's sheet, select **New server grant**.
3. Pick a **Certificate**. Only certificates with a current version are listed.
4. Optionally pick a **Layout**. Without one, the target's own field names are used. Layouts that hold a PKCS#12, JKS or DER file are disabled with the hint "PEM layouts only".
5. Select **Grant**.

You need `clients:write` to add, edit, redeploy or remove server grants. You also need `keys:export` when the target sends the private key.

The sheet header repeats the target's type, a "Server" chip, an "Includes key" chip when the key is sent, and a "Stored secrets" chip when it holds any. **Edit** opens the target's settings.

Each grant shows a status:

| Status | Meaning |
|---|---|
| Pending | A deploy is queued or running. |
| Deployed | The current version is in Vault. The time of the deploy is shown. |
| Failed | The last attempt failed. Hover for the error. CertForge retries up to 5 times. |

A new certificate version, **Redeploy** and a changed layout all mark the grant Pending and start a new deploy. A grant on a certificate with no version yet stays Pending until one exists.

Per grant, three icon buttons sit on the row:

- **Redeploy** pushes the current version again, even if nothing changed.
- **Edit layout** changes the grant's layout. It is the only field you can change.
- **Remove** stops CertForge pushing this certificate. What is already in Vault stays. You confirm by typing the certificate name.

Redeploy also exists for client grants. See [Clients](clients.md).

## Grant a certificate to a client

Agent targets are granted from the client, in its grant editor, together with a file layout and hooks. A server target cannot be picked there. See [Clients](clients.md) and [Agents](agents.md#grants-and-reconcile).

## Layouts and hooks

The other two tabs of **Delivery** shape what an agent writes and runs for a grant:

- **File layouts** (**New layout**) describe the files an agent writes: path, format (PEM, DER, PKCS#12 or JKS), owner, group and mode. See [Agents](agents.md#file-layouts).
- **Hooks** (**New hook**) are commands an agent runs before or after it writes the files. An agent runs one only if its path is in the agent's `CF_HOOK_ALLOW`. See [Agents](agents.md#hooks-and-the-allowlist).

A layout or hook that grants use cannot be deleted.

## Secrets

A type can mark some settings as secret. Secret settings are stored encrypted and are never shown again. The form shows **Stored** with Replace and Remove once one is set. Leave it untouched to keep it. Neither shipped type has a secret setting today.

If you change a URL while keeping a stored secret, the save is refused with "re-enter the secret". A stored credential never moves to a new destination on its own.

## Options

| Setting | What it does | Default |
|---|---|---|
| **Allow loopback and link-local** (`notifications.allowLoopbackUrls`) | Lets server-run targets use loopback and link-local URLs. Cloud-metadata addresses are always refused. | Off |

Agent-run targets may always use loopback and link-local addresses. The setting is under **Settings → Integrations → Notifications**. See [the configuration reference](../reference/configuration.md#notifications-section).

## Common problems

**The Save button on a target is disabled.** The target would send the private key and you lack `keys:export`. Ask a global admin, or turn **Include private key** off.

**A server grant stays Pending.** The certificate has no version yet, or a deploy is queued or being retried. Issue the certificate first. If it stays Pending, hover the status for an error.

**A server grant shows Failed.** Hover the chip for the reason. Common causes are an unreachable Vault, a token without `create` and `update` on `<mount>/data/<path>`, or a wrong **Mount**. Fix the cause, then select **Redeploy**. See [Vault](vault.md#policy-needs).

**"Deploy target not found."** The link points at a target that was deleted. Reload the list.

**A grant is refused with a path conflict (409).** Another grant of this target renders the same Vault path. Add `{name}` or `{cert}` to **Path**.

**Layout choice is greyed out on a server grant.** It holds a non-PEM file. Pick a PEM-only layout.

**Delete is disabled on a target.** Grants still use it. The tooltip gives the count.

## See also

- [Agents](agents.md) for the agent side of Traefik, layouts and hooks
- [Vault](vault.md) for the connection a Vault KV target uses
- [Alerts](alerts.md) for `deploy.failed` and `deploy.drift` events
- [Certificates](certificates.md)
