# Backup

A backup is one encrypted file that holds your whole CertForge database: certificates, private keys, settings, users and the audit log. You can take one on demand, let the server write them on a schedule, and restore one onto a fresh database. You need backups to recover from a lost disk or to move CertForge to a new host.

Backups are encrypted with a key derived from your database's root secret, and that root secret is sealed by the encryption key (`CF_KEK`, `CF_KEK_FILE` or Vault Transit). The encryption key is not in the backup. See the [Security model](../operations/security-model.md) for how the key hierarchy works.

## Before you start

- Taking a backup from the UI or API needs the `settings:write` permission, which only a global admin has.
- **Keep a copy of the encryption key somewhere safe, outside the server.** Restoring a backup needs the same key that sealed it (the active key, or an older one you still have configured). Without it, no backup can be restored, and there is no way around that. See [the encryption key](../reference/configuration.md#the-encryption-key).
- The UI shows a reminder about this at the top of **Settings → Backups**. Select **Dismiss** to hide it in your browser.

## Back up on demand

1. Open **Settings → Backups**.
2. Select **Back up now**. The browser downloads a `certforge-<yyyymmddThhmmssZ>.cfbak` file and shows "Backup downloaded".

The same backup is available from other tools:

```bash
# from a shell, against a running server (needs an API key with the admin scope)
cfctl backup create --out /var/backups/certforge/manual.cfbak

# directly against the database, on the server host
certforge backup --out /var/backups/certforge/manual.cfbak

# to stdout, through compose
docker compose exec -T certforge certforge backup --out - > manual.cfbak
```

A backup takes one consistent snapshot of the database, so it is safe to run while the server is working. If something fails partway, the download is aborted instead of ending as a file that looks complete. A successful on-demand backup is recorded in the audit log as `backup.created`; a failed one as `backup.failed`. See [cfctl](../reference/cfctl.md) and [server commands](../reference/server-cli.md#backup).

## Backup schedule

The server can write a backup to a directory on its own host.

1. Open **Settings → Backups**.
2. Under **Schedule**, choose **Daily** or **Weekly**.
3. Enter a **Directory**: an absolute path on the server that already exists and is writable. In a container this must be a mounted volume, or the files vanish with the container.
4. Optionally change **Retain count**.
5. Select **Save**. The server creates and removes a test file in the directory, so a directory it cannot write to is rejected here.

An hourly job checks whether a backup is due. A backup is due once a day (or a week) has passed since the last scheduled one, or straight away if there has never been one, including right after a restart that missed its window. If a backup fails, the job waits an hour before trying again, so a full disk does not flood you with failure events.

Each run writes `certforge-<yyyymmddThhmmssZ>.cfbak` with mode `0600`, written under a temporary name and renamed when complete, so you never see a partial file. It then deletes the oldest `certforge-*.cfbak` files beyond **Retain count**, and any leftover temporary files more than an hour old.

While it runs, the server stages each table briefly, unencrypted, in a private directory under the OS temp directory (or `CF_BACKUP_SPOOL_DIR`). If `/tmp` is a memory-backed filesystem, set `CF_BACKUP_SPOOL_DIR` to a disk path. See [the server variables](../reference/configuration.md#server-environment-variables).

The **Status** card on the same page shows the result:

| Field | Meaning |
|---|---|
| **Last backup** | **Never**, **Succeeded** or **Failed**, with when. |
| **Size**, **File** | Size and name of the last archive written. |
| **Next** | When the next scheduled backup is due, or **Not scheduled**. |
| **Error** | Why the last backup failed (first 1000 characters). |

A successful scheduled run raises a `backup.completed` event and a failed one `backup.failed`, which your [alert channels](alerts.md) can deliver. See [events](../reference/events.md). While a schedule is on, `/readyz` shows a `backup` check that turns `degraded` after seven days without a successful backup. It never makes the server unready.

## Restore

Restore runs from the command line, with the server stopped. There is no restore button and no restore over HTTP. Restore into a fresh, never-started database: it refuses a target whose audit log already has events.

1. Create an empty Postgres database and point `CF_DATABASE_URL` at it.
2. Configure the same encryption key that sealed the backup (`CF_KEK`, `CF_KEK_FILE` or `CF_KEK_VAULT_*`). If the backup was made under an older key, set the older key as the previous key: see [Key management](../operations/key-management.md).
3. Stop any CertForge server using that database. Restore refuses while one is running.
4. Preview the archive. Without `--yes`, restore reads only the file's header, prints when it was created and which version and key it needs, and exits with code 2:

   ```bash
   certforge restore --in manual.cfbak
   ```

5. Restore for real:

   ```bash
   certforge restore --in manual.cfbak --yes
   ```

   Through compose, pipe the file in and disable the pseudo-terminal with `-T`:

   ```bash
   docker compose run --rm -T certforge restore --in - --yes < manual.cfbak
   ```

6. Start the server with `certforge serve`. It applies any newer migrations and carries on.

Restore loads every table in one transaction and checks each table's row count and hash against the archive. Before committing it checks that the restored root secret and the key canary match your configured key. If anything is wrong, the whole restore rolls back and no data is loaded. On success it adds `restore.completed` to the audit log.

## Options

| Field | What it does | Default |
|---|---|---|
| **Schedule** (`schedule`) | How often a backup is written to disk. | Off |
| **Retain count** (`retainCount`) | Scheduled files kept before the oldest is deleted. | 7 (1–90) |
| **Directory** (`directory`) | Absolute path for scheduled backups. Required when a schedule is on. | none |

The bounds are listed in the [configuration reference](../reference/configuration.md#backups).

## Common problems

**Saving the schedule says the directory is required or is not a writable directory.** The path must be absolute, exist, and be writable by the server's user (uid 65532 in the container). Create it or fix the mount, then save again.

**Restore says a CertForge server is running.** Stop every server that uses the database, then retry. A running `serve` holds a lock that blocks restore, and a restore in progress blocks `serve` from starting.

**Restore says the target must be a fresh database.** The audit log in the target is not empty. Create a new empty database; restore never overwrites one that is in service.

**Restore fails with a key mismatch.** The configured key cannot open the archive. Use the key (or previous key) that was active when the backup was taken. You can read which key it needs from the preview in step 4.

**Last backup shows Failed.** Read **Error**. A full disk or a revoked directory are typical. The next attempt happens an hour after the failure.

**`/readyz` shows `backup: degraded`.** No backup has succeeded in seven days while a schedule is on. Fix the cause shown in **Error**.

## See also

- [Key management](../operations/key-management.md)
- [Configuration reference](../reference/configuration.md#backups)
- [Server commands](../reference/server-cli.md)
- [Security model](../operations/security-model.md)
- [Settings](settings.md)
