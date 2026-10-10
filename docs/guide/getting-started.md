# Getting started

This page takes you from nothing to a running CertForge with one issued certificate. You need Docker with Compose, a machine that can reach the internet (to pull images), and about ten minutes.

## Before you start

CertForge stores everything in Postgres and encrypts private keys and secrets with one **encryption key** (called the KEK in environment variable names). You create that key before the first start. If you lose it, nothing it protects can be decrypted, backups included.

## Install with Compose

1. Get the repository (the compose files live in `deploy/`):

   ```bash
   git clone https://github.com/metril/certforge.git
   cd certforge
   ```

2. Create the encryption key. The container runs as user `65532`, so that user must be able to read the file:

   ```bash
   mkdir -p deploy/secrets
   head -c 32 /dev/urandom | base64 > deploy/secrets/kek
   sudo chown 65532 deploy/secrets/kek && chmod 0400 deploy/secrets/kek
   ```

   Copy `deploy/secrets/kek` somewhere safe now. To keep the key in Vault instead of a file, see [Vault](vault.md#transit-kek).

3. Start the stack. Build from source:

   ```bash
   docker compose -f deploy/compose.yaml up -d --build
   ```

   Or run a published image. Pin a version in production:

   ```bash
   CF_VERSION=0.9.0 docker compose -f deploy/compose.release.yaml up -d  # x-release-please-version
   ```

4. Check that the server is ready:

   ```bash
   curl -s localhost:8080/readyz
   ```

The compose files read these optional variables:

| Variable | What it does | Default |
|---|---|---|
| `CF_HTTP_PORT` | Host port for the UI, API and agent protocol | `8080` |
| `CF_AGENT_PORT` | Host port for the second, optional agent listener | `8443` |
| `CF_BASE_URL` | The public URL of CertForge | `http://localhost:<CF_HTTP_PORT>` |
| `CF_DB_PASSWORD` | Postgres password | `certforge` |
| `CF_LOG_LEVEL` | `debug`, `info`, `warn` or `error` | `info` |
| `CF_VERSION` | Image tag (release file only) | `latest` |

For ports, reverse proxies and every server setting, see [Deploying](../operations/deploying.md) and [Configuration](../reference/configuration.md).

## First-run setup wizard

Open `http://localhost:8080` (or your `CF_BASE_URL`). Until setup is done, every page redirects to the wizard. It has four steps, and the step bar at the top lets you jump back.

1. **Admin password**: choose the password for the local admin account, at least 12 characters, and confirm it. This is your break-glass login. If the server was started with `CF_SETUP_TOKEN` or `CF_SETUP_TOKEN_FILE`, a **Setup token** field appears first; enter that token to claim the server.
2. **Base URL**: the address people and agents use to reach CertForge. It is pre-filled from your browser. A note says whether it **Matches this browser** or **Differs from this browser's address**, and a warning appears for `http://` because sign-in cookies and API keys cross this address. Links in notifications use this URL.
3. **Encryption key**: the wizard checks that the key loaded (`CF_KEK`, `CF_KEK_FILE` or Vault Transit through `CF_KEK_VAULT_ADDR`) and that the database is reachable. If a check fails, fix the environment, restart, and select **Check again**. You cannot continue until the key passes.
4. **First organization**: give the organization a name. The **Slug** is filled in for you; it appears in URLs (`/o/<slug>/…`), uses lowercase letters, digits and hyphens, and never changes.

Select **Finish setup**. CertForge creates the admin and the organization, signs you in as a global admin, and opens **Issuers → CAs** with the new-CA panel ready. Setup runs once; the wizard is gone afterwards.

To sign in later, open the login page and enter the admin password. If you turn on single sign-on, the password form moves behind **Break-glass login** (see [Access](access.md#single-sign-on)). If you forget the password, reset it from the server host with `certforge bootstrap-admin` ([Server commands](../reference/server-cli.md)).

## Issue your first certificate

The quickest first certificate comes from CertForge's own private CA, because it needs no DNS or internet validation. For a public certificate, see [Issuers](issuers.md) and [Challenges](challenges.md).

1. In **Issuers → CAs**, select **Add CA** (the panel from the wizard may already be open). Set **Type** to **Built-in CA**, enter a **Name**, fill the subject's **Common name**, and select **Save CA**. The root and issuing keys are created for you.
2. Select **Certificates** in the sidebar, then **New certificate**.
3. **Names**: type the names to cover, for example `app.example.internal`.
4. **Verification**: private CAs do not need to prove control of the names, so there is nothing to set up.
5. **Options**: choose your Built-in CA under **Certificate authority**.
6. **Review**: give the certificate a **Certificate name** and select **Issue certificate**.

The certificate opens on its own page and turns **Active** when issuance finishes. To trust it in browsers and tools, download the CA's trust bundle from the CA's detail panel ([Issuers](issuers.md#trust)).

## Deliver it to a host

Install the agent on the host that needs the certificate, then grant the certificate to that client.

1. Make sure agents can reach the server by name: set `CF_BASE_URL`, or **Settings → Agents → Agent URL**, to an address reachable from the agent host. Every token carries it.
2. Open **Clients** and select **Enrol client**. Enter a name, choose **Create token**, and copy the `docker run` line or Compose file.
3. Run it on the host.
4. The agent connects and the panel shows **Agent enrolled. Awaiting approval.** Approval is on by default: select **Review**, compare the verification code with the agent's log, and approve. See [Clients](clients.md#approval).
5. On the client, select **Grant certificate** and pick the certificate and where its files go. See [Delivery](delivery.md).

## Common problems

**The wizard stays on Encryption key.** The server could not load the key. Check that `CF_KEK_FILE` points at a readable file (the container user is `65532`), or that `CF_KEK` or the Vault Transit variables are set. The failing check is listed with its message.

**The wizard says the setup token was not accepted.** The token must match `CF_SETUP_TOKEN` exactly (at least 16 characters). Go back to the first step and re-enter it.

**`/readyz` returns 503.** The database or the key is not ready. The response names the failing check. See [Troubleshooting](../operations/troubleshooting.md).

**You see the login page instead of the wizard.** Setup already ran. Sign in with the admin password, or reset it with `certforge bootstrap-admin`.

## See also

- [Overview](overview.md): what each part of the UI shows.
- [Configuration](../reference/configuration.md#the-encryption-key): the encryption key in detail.
- [Backup](backup.md): set up backups before you rely on the install.
