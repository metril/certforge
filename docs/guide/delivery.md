# Delivery

Delivery is how a certificate reaches the place that uses it. A **deploy target** says what to do with a certificate besides writing files, such as updating Traefik or storing the files in Vault. A **grant** links one certificate to one target or client. Open **Delivery** in the sidebar to manage targets, file layouts, hooks and saved credentials.

Three target types ship with CertForge:

| Type | Runs on | Private key |
|---|---|---|
| Traefik (`traefik`) | An agent | Always sent |
| Vault KV (`vault-kv`) | The server | Only if you switch on **Include private key** |
| Authentik (`authentik`) | The server | Always sent |
| SSH (`ssh`) | The server | Only when a file uses `key` or `bundle` |
| pfSense Plus (`pfsense`) | The server | Always sent |
| TrueNAS SCALE (`truenas`) | The server | Always sent |
| MikroTik RouterOS (`routeros`) | The server | Always sent |

## Before you start

- You need the `delivery:write` permission to add or edit targets. Viewers can open a target read-only.
- Delivery belongs to one org, so it is not offered under **All orgs**.
- A Traefik target needs an enrolled agent. See [Clients](clients.md) and [Agents](agents.md).
- A Vault KV target needs Vault configured first. See [Vault](vault.md#integrations).

## Add a deploy target

1. Open **Delivery → Deploy targets** and select **Add target**.
2. Enter a **Name**.
3. Pick a **Type**. Each choice carries a chip for where it runs.
4. For SSH, pfSense Plus, TrueNAS SCALE, MikroTik RouterOS and Authentik, pick a **Credential**: **Enter manually**, or a [saved credential](#saved-credentials) of a kind the type accepts.
5. Fill in the **Settings** the type shows. The fields are listed under [Traefik](#traefik) and [Vault KV](#vault-kv).
6. Select **Save**.

The list shows each target as its name over a muted line: the type, where it writes (a directory, path or URL), and either the saved credential it uses or "secrets stored" if it holds its own. The **Runs on** column shows Server or Agent. **Used by** shows how many grants use it.

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
| **Certificate directory on the agent** (`certsDir`) | Absolute directory for `fullchain.pem` and `privkey.pem`. Setting it needs the `delivery:write` permission. Must not equal the target's **Directory on the agent**. | `<dir>/certs/<name>` |
| **Certificate directory as Traefik sees it** (`certsDirTraefik`) | The same directory as Traefik sees it. | Derived from `dir` and `pathPrefix` when `certsDir` is under `dir`, else the same as `certsDir` |
| **TLS stores** (`stores`) | Overrides the target's stores for this certificate. | The target's |

On upgrade, a target's Default certificate moves to one grant per client, directory and store set (the same key the 409 rule uses): the certificate whose name sorts first, which is what Traefik was serving. Change it in the grant if another certificate should be the default.

The target no longer has a `defaultCert` field. Migration 00026 moved it onto the grants of each target that had it on. An agent older than this change ignores the options: on the default grant's next deploy it writes the YAML without `defaultCertificate`, and Traefik stops serving the default certificate. Upgrade agents right after the server. A new agent fails to parse a stale target-level `defaultCert` from an old server, so upgrade the server first.

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

1. Enroll the agent. See [Clients](clients.md).
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

## Authentik

An Authentik target pushes a certificate and its private key into Authentik's certificate-keypair store, so Authentik's own TLS or signing uses it. It runs on the server, so its grants have no client.

| Field | What it does | Default |
|---|---|---|
| **URL** (`url`) | The `https` URL of the Authentik instance. | None |
| **API token** (`token`) | An Authentik API token that can view, add and change certificate-key pairs. Stored encrypted. | None |
| **Keypair name** (`name`) | Name of the keypair in Authentik, letters, digits, space, `.`, `_` and `-`. | The certificate's name |
| **CA certificate** (`caPem`) | PEM to trust for Authentik's TLS certificate, on top of the system roots. | None |
| **Timeout** (`timeoutSeconds`) | Seconds per request, 5 to 120. | 30 |

Each deploy looks the keypair up by exact name. If it exists it is updated in place, so brands, providers and outposts keep pointing at it. Otherwise it is created. If two keypairs share the name the deploy fails. When Authentik already holds the same certificate, nothing is written.

## SSH

An SSH target writes certificate files to a remote host and runs optional commands before and after. Use it for devices with no certificate API, such as PiKVM and the GL.iNet Comet KVM. It runs on the server, so its grants have no client.

| Field | What it does | Default |
|---|---|---|
| **Host**, **Port** (`host`, `port`) | The SSH server. | Port 22 |
| **Username** (`username`) | Login name. | None |
| **Password**, **Private key** (`password`, `privateKey`) | At least one. The key is PEM and must not have a passphrase. Stored encrypted. | None |
| **Host key** (`hostKey`) | The pinned server key, a `known_hosts` line or `<type> <base64>`. Required: there is no trust on first use, and a mismatch fails before anything runs. | None |
| **Files** (`files`) | 1 to 16 entries of `path` (absolute), `content` and `mode`. `content` is `fullchain`, `cert`, `chain`, `key`, `bundle` (fullchain plus key, as HAProxy and lighttpd want) or the name of a file from the grant's layout. | Mode `0644` |
| **Command before writing** (`preCommand`) | Run first. A non-zero exit aborts the deploy. | None |
| **Command after writing** (`postCommand`) | Always run when set, even after a failed write, so state is restored. | None |
| **Timeout** (`timeoutSeconds`) | Seconds for the whole deploy, 5 to 300. | 60 |

Get the host key with `ssh-keyscan -t ed25519 <host>` and paste the key line it prints. Compare it with the device's own fingerprint if you can.

The private key is sent only when a file asks for `key` or `bundle` (or a layout file, which may hold it), and needs the `keys:export` permission. Files are written atomically with a restrictive umask, then set to the chosen mode.

**PiKVM and GL.iNet Comet.** Their root filesystem is read-only, so the **PiKVM / GL.iNet Comet** preset wraps the write: `rw` before, then `ro; systemctl restart kvmd-nginx` after. It writes `/etc/kvmd/user/ssl/server.crt` and `server.key`. Older PiKVM images use `/etc/kvmd/nginx/ssl/`: pick **PiKVM (legacy paths)**. Log in as `root`.

Every command the SSH target runs, before or after the files, is recorded as a hook run. Open the target and pick the **Hook runs** tab to see the command, exit status, duration and output (8 KiB each).

## pfSense Plus

A pfSense Plus target pushes a certificate into pfSense through the Netgate Nexus REST API (pfSense Plus 25.03 or later). It runs on the server, so its grants have no client. The API is new and its details may change between releases.

| Field | What it does | Default |
|---|---|---|
| **API URL** (`url`) | https URL of the Nexus API, for example `https://fw.example.net:8443/api`. | None |
| **Username**, **Password** (`username`, `password`) | A pfSense user allowed to manage certificates. The password is stored encrypted. | None |
| **Device** (`device`) | Name, alias or ID of the firewall in Nexus. | The only managed device |
| **Certificate name** (`certName`) | Description of the certificate in pfSense, letters, digits, space, `.`, `_` and `-`. | The certificate's name |
| **Use for the WebGUI** (`setWebGuiCert`) | Also select this certificate for the pfSense web interface. | Off |
| **Restart services that use it** (`restartServices`) | After deploying, restart every pfSense service that uses this certificate: the WebGUI, OpenVPN, IPsec, captive portal and packages. | On |
| **CA certificate** (`caPem`) | PEM to trust for pfSense's TLS certificate, on top of the system roots. | None |
| **Timeout** (`timeoutSeconds`) | Seconds per request, 5 to 120. | 30 |

Each deploy logs in, then looks the certificate up by its description. If it exists it is updated in place, so WebGUI, OpenVPN and HAProxy references keep pointing at it. Otherwise it is created. If two certificates share the name the deploy fails. When pfSense already holds the same certificate, nothing is written.

With **Restart services that use it** on, every deploy then asks pfSense which services use the certificate and restarts exactly those, because Nexus restarts none of them itself. This runs even when the certificate was unchanged, since an earlier deploy may have left a service on the old one. The deploy detail lists what was restarted. The pfSense user needs the privileges to run PHP and shell commands through the device API (the diag command privileges). If the restart fails the deploy reports an error, although the certificate is already in place.
## TrueNAS SCALE

A TrueNAS target imports the certificate into TrueNAS SCALE 25.10 or later over its WebSocket API and can make it the web UI certificate. It runs on the server.

| Field | What it does | Default |
|---|---|---|
| **URL** (`url`) | https URL of the TrueNAS web UI. | None |
| **Username** (`username`) | The user the API key belongs to. | `root` |
| **API key** (`apiKey`) | A TrueNAS API key (Credentials, Local Users). Stored encrypted. | None |
| **Certificate name prefix** (`certPrefix`) | Imports are named `<prefix>-<8 hex of the fingerprint>`. | `certforge` |
| **Use as web UI certificate** (`setUiCert`) | Set the UI certificate and restart the UI. | On |
| **CA certificate** (`caPem`) | PEM to trust for TrueNAS's TLS certificate. | None |
| **Timeout** (`timeoutSeconds`) | Seconds for the whole deploy, 10 to 300. | 120 |

A certificate already on the box with the same fingerprint is reused, not imported again. Older certificates with the prefix are deleted after the switch; one still in use is left alone, and any other failure shows as a warning in the result.

## MikroTik RouterOS

A RouterOS target installs a certificate on RouterOS 7.x. It runs on the server. RouterOS has no POSIX shell, so the certificate and key are uploaded over SCP and then imported and bound through the REST API.

| Field | What it does | Default |
|---|---|---|
| **REST URL** (`url`) | https URL of the router, for example `https://router.example.net`. The REST API is served by `www-ssl`. | None |
| **Username**, **Password** (`username`, `password`) | A user allowed to use SSH and REST and to manage certificates. The password is used for both and stored encrypted. | None |
| **SSH port** (`sshPort`) | Port for the SCP upload. | 22 |
| **SSH host key** (`hostKey`) | The router's pinned SSH public key, from `ssh-keyscan -t ed25519 <host>`. | None |
| **Certificate name prefix** (`certName`) | Certificates are named `<prefix>-<fingerprint>`. | `certforge` |
| **Services** (`services`) | Where to bind it: `www-ssl`, `api-ssl`, `sstp`, `ovpn`. | `www-ssl`, `api-ssl` |
| **CA certificate** (`caPem`) | PEM to trust for the router's REST TLS certificate, on top of the system roots. | None |
| **Timeout** (`timeoutSeconds`) | Seconds per request, 10 to 300. | 90 |

Each deploy checks whether the router already holds the certificate by fingerprint. If not, it uploads `cf-<id>.crt` and `cf-<id>.key`, imports them, renames the certificate and removes the uploaded files. It then binds the certificate to each chosen service and removes older certificates named `<prefix>-<fingerprint>`. Cleanup failures are reported as warnings. Binding `www-ssl` restarts the REST service, so a deploy to a router you reach through that service may drop its own connection after the last step.

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
- **Edit layout** changes the grant's layout and post action.
- **Remove** stops CertForge pushing this certificate. What is already in Vault stays. You confirm by typing the certificate name.

### Post actions

A server grant can run one command after a successful deploy, for example `systemctl reload nginx` on the host that serves the certificate. Switch **Post action** on in the grant form, pick an existing [SSH](#ssh) target and enter the command (up to 512 characters) and a timeout of 5 to 300 seconds. The post action reuses that target's host, credentials and pinned host key; its files and own commands are not used. Any server-run target type can have one.

The run is recorded on the **Hook runs** tab of the grant's target. A non-zero exit, or a connection failure, marks the deployment Failed: the error says the certificate deployed but the post action failed, and CertForge retries. An SSH target that grants use as a post action cannot be deleted until you remove those post actions.

Redeploy also exists for client grants. See [Clients](clients.md).

## Grant a certificate to a client

Agent targets are granted from the client, in its grant editor, together with a file layout and hooks. A server target cannot be picked there. See [Clients](clients.md) and [Agents](agents.md#grants-and-reconcile).

## Layouts and hooks

The other two tabs of **Delivery** shape what an agent writes and runs for a grant:

- **File layouts** (**New layout**) describe the files an agent writes: path, format (PEM, DER, PKCS#12 or JKS), owner, group and mode. See [Agents](agents.md#file-layouts).
- **Hooks** (**New hook**) are commands an agent runs before or after it writes the files. An agent runs one only if its path is in the agent's `CF_HOOK_ALLOW`. See [Agents](agents.md#hooks-and-the-allowlist). A hook of kind **Restart** restarts a Docker container or systemd unit instead, if the agent lists it in `CF_RESTART_ALLOW`; see [Restart hooks](agents.md#restart-hooks).

A layout or hook that grants use cannot be deleted.

## Saved credentials

A saved credential holds a login once so many targets can use it. When the same SSH key or router password is on ten hosts, you rotate it in one place.

1. Open **Delivery → Credentials** and select **Add credential**.
2. Enter a **Name** and pick a **Kind**. The kind is fixed once the credential exists.
3. Fill in its fields and select **Save credential**.

| Kind | Fields | Accepted by |
|---|---|---|
| SSH | Username, plus a password, a private key or both | SSH |
| Password | Username and password | SSH, pfSense Plus, MikroTik RouterOS |
| API key | API key, optional username | TrueNAS SCALE |
| Token | Token | Authentik |

In a target, pick the credential under **Credential**. The fields it supplies are hidden and come from the credential at deploy time. Attaching a credential removes the target's own stored secrets. Pick **Enter manually** to detach it and type the login again. A target's detail sheet links to the credential it uses.

Editing a credential redeploys nothing. Server targets use the new value on their next deploy, and agents that use it get it on their next sync. **Used by** counts the targets that use a credential. A credential in use cannot be deleted; detach it from those targets first.

Permissions:

- `deploycreds:read` lists credentials. Viewers and up have it.
- `deploycreds:write` adds, edits and deletes them. Org admins and admins have it; operators do not.
- Attaching a credential to a target, or changing the URL, host, port or pinned host key of a target that uses one, also needs `deploycreds:write`. Without it the **Credential** select and **Save** are disabled.
- A global admin can show a stored value with the eye button (`deploycreds:reveal`). This is audited.

## Secrets

A type can mark some settings as secret. Secret settings are stored encrypted and are never shown again. The form shows **Stored** with Replace and Remove once one is set. Leave it untouched to keep it. Neither shipped type has a secret setting today.

If you change a URL while keeping a stored secret, the save is refused with "re-enter the secret". A stored credential never moves to a new destination on its own.

## Options

| Setting | What it does | Default |
|---|---|---|
| **Allow loopback and link-local** (`notifications.allowLoopbackUrls`) | Lets server-run targets use loopback and link-local URLs. Cloud-metadata addresses are always refused. | Off |

Agent-run targets may always use loopback and link-local addresses. The setting is under **Settings → Integrations → Notifications**. See [the configuration reference](../reference/configuration.md#notifications-section).

## Trusting a private CA

Some forms have a CA certificate field for a server whose HTTPS certificate does not chain to a public root: pfSense, TrueNAS, RouterOS and Authentik targets, AD CS and custom ACME CAs, Vault, and ntfy, Home Assistant and webhook channels. The field holds one or more PEM certificates, added to the system roots. Each way below adds the certificates the field does not already hold, so a root and an intermediate can come from different places. Clear the field to start over.

- **Paste** the PEM text. The summary under the field lists each certificate's common name and expiry, and warns about text that is not a certificate. The server checks the field again on save.
- **Upload** a `.pem`, `.crt`, `.cer` or `.der` file. A DER file is converted to PEM in the browser.
- **Fetch from server** reads the chain the server presents and lets you pick the certificates to add; the topmost CA is picked by default. It uses the form's URL, or a `host:port` you type. CertForge connects from its own server under the same address policy as server-run targets (see [Options](#options)), so a host only an agent can reach will not answer. It needs `delivery:write` or `cas:write`. This is trust on first use: anything between CertForge and the server could present its own chain, so compare the SHA-256 fingerprint with the one the server shows on its own console or web UI before you save.
- **From saved CA** copies the certificate of a CA in this organization, such as a Built-in CA, a Vault PKI CA or an AD CS CA. It is a copy: pick the CA again after it rotates to a new root.

## Common problems

**The Save button on a target is disabled.** The target would send the private key and you lack `keys:export`. Ask a global admin, or turn **Include private key** off.

**A server grant stays Pending.** The certificate has no version yet, or a deploy is queued or being retried. Issue the certificate first. If it stays Pending, hover the status for an error.

**A server grant shows Failed.** Hover the chip for the reason. Common causes are an unreachable Vault, a token without `create` and `update` on `<mount>/data/<path>`, or a wrong **Mount**. Fix the cause, then select **Redeploy**. See [Vault](vault.md#policy-needs).

**"Deploy target not found."** The link points at a target that was deleted. Reload the list.

**A grant is refused with a path conflict (409).** Another grant of this target renders the same Vault path. Add `{name}` or `{cert}` to **Path**.

**Layout choice is grayed out on a server grant.** It holds a non-PEM file. Pick a PEM-only layout.

**Delete is disabled on a target.** Grants still use it. The tooltip gives the count.

## See also

- [Agents](agents.md) for the agent side of Traefik, layouts and hooks
- [Vault](vault.md) for the connection a Vault KV target uses
- [Alerts](alerts.md) for `deploy.failed` and `deploy.drift` events
- [Certificates](certificates.md)
