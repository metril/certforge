# Key management

CertForge uses two kinds of keys you can rotate: the encryption key that protects every secret in the database, and the agent CA that signs agent identities. Both rotate while the server keeps running. This page walks through each.

## Before you start

- Rotating either key needs the `settings:write` permission, which only a global admin has.
- Take a [backup](../guide/backup.md) first, and keep a copy of every encryption key you have used. A backup can only be restored with the key that sealed it.
- Where the encryption key lives, its format and all its variables are in the [configuration reference](../reference/configuration.md#the-encryption-key).

## Encryption key rotation

The encryption key (KEK, for key-encryption key) wraps the data key of every secret. To replace it you configure the new key as the active one, keep the old key as the previous one, let the server re-encrypt everything, and then drop the old key. During the changeover the server can read rows under either key, so nothing stops.

**Settings → Backups** has an **Encryption key** card. Normally it is one quiet row with the chip **Key check OK**. Once an older key is configured, a re-encryption is running or unfinished, or the key check fails, it expands to show the steps **New key set**, **Re-encrypting** and **Remove the old key**, with these fields:

| Field | Meaning |
|---|---|
| **Kind** | Static (a key from the environment) or Vault Transit (the key never leaves Vault). |
| **Key ID** | Identifier stored with every encrypted row. |
| **Key check** | **Key check OK** or **Key check failed**: whether the active key decrypts a known test value. |
| **Older keys** | Previous keys still accepted for reading, or **None**. |

### Rotate a static key

1. Generate a new key: `head -c 32 /dev/urandom | base64`. Store a copy somewhere safe.
2. Move the current value of `CF_KEK` (or `CF_KEK_FILE`) to `CF_KEK_PREVIOUS` (or `CF_KEK_PREVIOUS_FILE`). Set the new key as `CF_KEK` (or `CF_KEK_FILE`).
3. Restart the server. On boot it starts a re-encryption automatically.
4. Watch the **Encryption key** card, or run `cfctl keys status` until `rewrapRemaining` reaches 0. To start a fresh run at any time, select **Re-encrypt now** or run `cfctl keys rewrap`.
5. When nothing remains, delete `CF_KEK_PREVIOUS` (or `CF_KEK_PREVIOUS_FILE`) and restart. Every row now opens with the new key alone.

### Move to Vault Transit, or between Vault keys

The steps are the same, with the roles swapped. Configure the new Transit key as active with `CF_KEK_VAULT_ADDR` and the other `CF_KEK_VAULT_*` variables (see [Vault](../guide/vault.md#transit-kek)), and set the old key as previous: `CF_KEK_PREVIOUS` for a static key, or `CF_KEK_PREVIOUS_VAULT_*` for an older Transit key. Moving from a static key to Transit needs the old static key as the previous key on the first boot, because the server must read the rows still sealed under it. You may set one static and one Vault previous key at the same time.

To move from Transit back to a static key, set the new static key as `CF_KEK` and the Transit key as `CF_KEK_PREVIOUS_VAULT_*`.

### Rotate a key version inside Vault

Rotating a Transit key's version in Vault does not change its Key ID, and CertForge keeps working. To move existing rows onto the newest version, start a re-encryption: the server also does this by itself on every boot. The **Re-encrypt now** button stays disabled when no older key is configured, so use `cfctl keys rewrap` or `POST /api/v1/keys/rewrap`.

### Re-encryption

The server visits each table that holds sealed data and moves every row still sealed under an older key onto the active one. The tables are: `settings`, `cas`, `acme_accounts`, `dns_provider_credentials`, `output_specs`, `agent_cas`, `certificate_versions`, `notification_channels` and `deploy_targets`.

- It re-encrypts the key check value first, so a missing or misconfigured older key fails the run at once, before it scans the large tables.
- Progress shows per table on the card, with **Running**, **Failed** or **Finished**, and the count remaining. The card polls while a run is active.
- It is safe to stop, resume or run again. A row already on the active key is skipped, and a write that loses a race with another write is retried by the next run instead of overwriting data.
- Starting a second run while one is active returns 409 (the card says "Re-encryption is already running").
- A run is recorded in the audit log as `kek.rewrap_started` and `kek.rewrap_finished`.

If you remove the previous key before `remaining` reaches 0, the rows it still protects cannot be read until you configure it again. The failure is loud and nothing is lost.

At most one static previous key and one Vault previous key are accepted, and a previous key that is the same as the active key is a startup error.

## Agent CA rotation

The agent CA signs every agent's identity certificate and the agent listener's certificate. You can have several; one is **Active** and signs new agent certificates. **Settings → Agents** lists them under **Agent CAs**, above the **Listener certificate** card (**Names**, **Expires**, **Issued by**). Each CA shows its status (**Active**, **Retiring** or **Retired**), its fingerprint, **Valid until** and how many agents still use it. A CA is valid for ten years.

### Rotate the CA

1. Open **Settings → Agents** and select **Rotate**. Type `rotate` to confirm.
2. A new CA becomes **Active** and signs every new agent certificate. The old one becomes **Retiring**: it stays trusted and keeps signing the listener certificate, so every existing agent can still connect.
3. Connected agents receive the new trust bundle, renew at once from the new CA, and reconnect.
4. Agents in [pull mode](../guide/agents.md#pull-mode) and agents that were offline move when their certificate comes due for renewal (at two thirds of its lifetime, 60 days by default). The renew response carries the new trust bundle. To move one sooner, re-enrol it.

Unused enrolment tokens keep working until the old CA is retired.

### Retire the old CA

1. Wait until the retiring CA shows 0 agents (the count of unexpired certificates of active clients it signed).
2. Select **Retire** next to it and type `retire` to confirm. **Retire** is disabled while any agent still uses the CA, and only a **Retiring** CA can be retired.
3. The listener certificate is re-issued by the remaining oldest CA. By then every active agent trusts it.

Enrolment tokens pin the CA that signs the listener certificate. A token created before the old CA was retired cannot be used afterwards, because the agent refuses a server chain that lacks the pinned CA. Re-enrol that client to get a new token.

Rotate and retire are recorded as `agent_ca.rotate` and `agent_ca.retire`. The API is `GET /agents/ca`, `POST /agents/ca/rotate` and `POST /agents/ca/{id}/retire`; see the [API reference](../reference/api.md).

## Common problems

**The server will not start after changing the key.** The new key cannot open the sealed root secret. Put the old key back, or set it as the previous key, and restart. A fresh database accepts any first key.

**`/readyz` reports `kek: failed`, or the card shows Key check failed.** The root secret opens but the key check does not. Confirm you configured the key you meant to, and any previous key too.

**Re-encryption shows Failed.** Read the message next to the chip. A removed or misconfigured previous key is the usual cause. Restore it and select **Re-encrypt now**.

**Startup says the previous key names the same key as the active key.** Remove `CF_KEK_PREVIOUS*` or set a different key.

**Retire is disabled.** Some agents still hold a certificate from that CA. Wait for them to renew, or re-enrol them.

**An agent cannot enrol after a CA retire.** Its token pinned the retired CA. Re-enrol the client.

**The listener is not running.** The agent listener certificate could not be issued at startup. Fix the cause shown in the server log and restart the server.

## See also

- [Backup](../guide/backup.md)
- [Configuration reference](../reference/configuration.md#the-encryption-key)
- [Vault](../guide/vault.md#transit-kek)
- [Agents](../guide/agents.md)
- [Security model](security-model.md)
