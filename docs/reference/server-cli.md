# Server commands

The `certforge` binary runs the server and a few offline operations. In the container image the entry point is `certforge` and the default command is `serve`. For commands that talk to a running server over the API, use [cfctl](cfctl.md).

```
certforge <command> [flags]
```

Run `certforge help` (or `-h`, `--help`) to list the commands.

All commands except `version`, `help` and `healthcheck` read the [server environment variables](configuration.md#server-environment-variables) and need at least `CF_DATABASE_URL` and an encryption key (`CF_KEK`, `CF_KEK_FILE` or `CF_KEK_VAULT_ADDR`).

## Commands

| Command | What it does |
|---|---|
| `serve` | Runs the server. |
| `migrate` | Applies database migrations and prints `schema version <n>`. |
| `bootstrap-admin` | Resets the local admin password after first-run setup. |
| `healthcheck` | Probes `/readyz` on the local listener. |
| `backup` | Writes an encrypted backup archive. |
| `restore` | Restores an encrypted backup archive. Offline only. |
| `version` | Prints the version. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | The command failed. The error is printed to stderr as `certforge <command>: <error>`. |
| `2` | Usage error (no command, unknown command), or `restore` run without `--yes`. |

## serve

```
certforge serve
```

Takes no flags. At startup it takes a shared database lock, applies any pending migrations (safe to run repeatedly and from several processes), then listens on `CF_LISTEN_HTTP` and `CF_LISTEN_AGENT`. It stops gracefully on `SIGINT` or `SIGTERM`, waiting up to 15 seconds for requests to finish. It refuses to start while a `restore` holds the database lock. If the agent listener certificate cannot be issued at startup, the agent listener does not start; fix the cause and restart.

## migrate

```
certforge migrate
```

Applies pending migrations without starting the server. You rarely need it, because `serve` migrates on startup.

## bootstrap-admin

Reset the local admin password from the server host, after first-run setup has completed. This also revokes all of that user's sessions and clears the account's disabled flag. The password must be at least 12 characters.

```bash
docker compose exec -e CF_ADMIN_PASSWORD='new long password' certforge certforge bootstrap-admin
# or
printf '%s\n' 'new long password' | certforge bootstrap-admin --password-stdin
```

| Flag | What it does |
|---|---|
| `--password-stdin` | Read the new password from the first line of stdin instead of `CF_ADMIN_PASSWORD`. |

Before setup completes there is no local admin to reset, and the command refuses rather than create one outside the setup wizard. Finish the [setup wizard](../guide/getting-started.md) first.

## healthcheck

```
certforge healthcheck
```

Sends `GET /readyz` to `CF_LISTEN_HTTP` (default `:8080`; an empty or wildcard host becomes `127.0.0.1`) with a 5-second timeout. It prints `ok` and exits `0` when the server answers 200, and exits `1` otherwise. The compose files use it as the container health check. See [Monitoring](../operations/monitoring.md) for what `/readyz` checks.

## backup

```
certforge backup --out <path|-> 
```

| Flag | What it does |
|---|---|
| `--out <path>` | Required. File to write, or `-` for stdout. |
| `--kek-escrowed` | Accepted so old scripts keep working. It does nothing. |

Streams one `.cfbak` archive. A file is written to a temporary name next to `--out` and renamed into place when complete, so a reader never sees a partial file. It prints `backup written to <path> (<bytes> bytes, <n> tables)`. It takes a read-only snapshot, so it is safe to run against a live server. See [Backup and restore](../guide/backup.md).

## restore

```
certforge restore --in <path|-> [--yes]
```

| Flag | What it does |
|---|---|
| `--in <path>` | Required. Archive to read, or `-` for stdin. |
| `--yes` | Actually restore. Without it, restore only prints the archive header and exits `2`. |

Restore refuses while a server is running against the database, and refuses a target whose audit log is not empty, so restore into a fresh database. The configured encryption key must be the one that sealed the archive (or a configured previous key). Full steps are in [Backup and restore](../guide/backup.md#restore).

## See also

- [Configuration reference](configuration.md)
- [cfctl](cfctl.md)
- [Backup and restore](../guide/backup.md)
- [Key management](../operations/key-management.md)
