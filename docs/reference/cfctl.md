# cfctl reference

`cfctl` is a small command-line client for CertForge's REST API. It checks server status, lists and acts on certificates, clients, notification channels, external monitors and events, reads the encryption key status or re-encrypts, takes an on-demand backup, and reads the audit log. It uses the same operations and permissions as the web UI. It talks to a running server only; for the offline `backup` and `restore` commands see [server-cli.md](server-cli.md).

## Install

Each [release](https://github.com/metril/certforge/releases) attaches static `cfctl_<tag>_linux_<amd64|arm64>.tar.gz` tarballs and a `SHA256SUMS` file. `<tag>` is the release tag, for example `v0.8.0`.

```bash
TAG=v0.8.0
curl -fsSLO https://github.com/metril/certforge/releases/download/$TAG/cfctl_${TAG}_linux_amd64.tar.gz
curl -fsSLO https://github.com/metril/certforge/releases/download/$TAG/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf cfctl_${TAG}_linux_amd64.tar.gz
sudo install -m 0755 cfctl /usr/local/bin/cfctl
```

`cfctl version` prints its own build version (`cfctl <version>`) and needs no URL or token. So do `cfctl help` and `cfctl -h`.

## Configuration

`cfctl` needs a server URL and an API key (create one under **Settings → Access → API keys**; see [Access](../guide/access.md)). Each value is resolved separately, and the first source that supplies it wins:

1. Flags `--url` and `--token`.
2. Environment variables `CFCTL_URL` and `CFCTL_TOKEN`.
3. The config file `$XDG_CONFIG_HOME/cfctl/config.json`, or `~/.config/cfctl/config.json` when `XDG_CONFIG_HOME` is unset:

   ```json
   {"url": "https://certforge.example.com", "token": "cf_ap1_xxxxxxxx"}
   ```

The config file must be mode `0600` (`chmod 0600 ~/.config/cfctl/config.json`). `cfctl` refuses to read one that any group or other can access.

`--token` on the command line is visible to every other process on the host (`ps`, `/proc/<pid>/cmdline`, shell history). Prefer `CFCTL_TOKEN` or the config file. `cfctl` prints a warning on stderr when the URL is not `https` and not a loopback address, because the token would travel in cleartext.

## Global flags

Global flags go before the command: `cfctl --org acme certs list`. A global flag placed after the command is rejected as unknown.

| Flag | Default | Meaning |
|---|---|---|
| `--url <url>` | `CFCTL_URL` | Server URL. |
| `--token <token>` | `CFCTL_TOKEN` | API key. |
| `--org <id\|slug>` | – | Organization to act on, as a UUID or a slug. Required by the commands marked below. |
| `--json` | off | Print the server's raw JSON instead of a table. With `--all`, one response body per page. |
| `--timeout <duration>` | `30s` | Per-request timeout, a Go duration such as `10s` or `2m`. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. Also `help` and `version`. |
| `1` | The server or the request failed. A problem response is printed as `error: <title>: <detail>`. Also an unreadable config file. |
| `2` | Usage error: unknown command or subcommand, a bad or misplaced flag, a missing argument or id, a missing URL or token, or an invalid `--since`. |

## Commands

Per-command flags go after the subcommand and before any id: `cfctl certs download --out cert.pem <id>`. An id is always a UUID.

| Command | Needs `--org` | What it does |
|---|---|---|
| `cfctl status` | no | Prints the server version. |
| `cfctl certs list` | no | Lists certificates. Without `--org`, lists every organization you can read. |
| `cfctl certs get <id>` | yes | Shows one certificate. |
| `cfctl certs renew <id>` | yes | Renews a certificate now. Prints `enqueued=true`. |
| `cfctl certs download <id>` | yes | Downloads a certificate version. |
| `cfctl clients list` | no | Lists clients. Without `--org`, lists every organization you can read. |
| `cfctl clients get <id>` | yes | Shows one client. |
| `cfctl channels list` | yes | Lists notification channels. |
| `cfctl channels test <id>` | yes | Sends a test notification through a channel. |
| `cfctl monitors list` | yes | Lists external monitors. |
| `cfctl monitors check <id>` | yes | Checks a monitor now. |
| `cfctl events list` | yes | Lists events. |
| `cfctl keys status` | no | Shows the encryption key status. |
| `cfctl keys rewrap` | no | Starts re-encrypting secrets under the active key. Fails with a conflict while one is running. |
| `cfctl backup create --out <path\|->` | no | Downloads an encrypted backup. |
| `cfctl audit list` | no | Lists audit events. |
| `cfctl version` | no | Prints the `cfctl` version. |
| `cfctl help` | no | Prints usage. |

### Flags by command

| Command | Flag | Default | Meaning |
|---|---|---|---|
| `certs list`, `clients list` | `--status <status>` | all | Filter by status. Certificates: `pending`, `active`, `failed`, `expired`, `revoked`. Clients: `pending`, `active`, `revoked`. |
| `certs download` | `--version <id>` | current version | Version id to download. |
| `certs download` | `--format pem\|der` | `pem` | File format. |
| `certs download` | `--parts <list>` | `fullchain,key` | Comma-separated: `cert`, `chain`, `fullchain`, `key`, `combined`. Parts that include the key need the `keys:export` permission. |
| `certs download` | `--out <path\|->` | `-` | File to write, or `-` for stdout. A file is written atomically. |
| `events list` | `--kind <kind>` | all | Only this [event kind](events.md). Repeat the flag for several kinds. |
| `events list` | `--severity <level>` | all | Minimum severity: `info`, `warning` or `critical`. |
| `events list` | `--since <time>` | – | Only events at or after this RFC 3339 time, for example `2026-10-01T00:00:00Z`. |
| `audit list` | `--action <action>` | all | An exact action such as `session.login`, or a prefix ending in a dot such as `client.`. See [Audit log](../guide/audit.md). |
| `backup create` | `--out <path\|->` | required | File to write, or `-` for stdout. |
| list commands | `--cursor <cursor>` | first page | Continue from a previous `nextCursor`. |
| list commands | `--all` | off | Follow every page, up to 100 pages. Applies to `certs list`, `clients list`, `events list` and `audit list`. |

## Examples

```console
$ cfctl --org acme status
FIELD    VALUE
version  1.4.0

$ cfctl --org acme certs list --status active
ID                                    NAME        STATUS  NOT AFTER
5b1e...                               example.com active  2026-12-01T00:00:00Z

$ cfctl --org acme certs renew 5b1e...
enqueued=true

$ cfctl --org acme certs download --parts fullchain,key --out /etc/tls/example.com.pem 5b1e...
wrote /etc/tls/example.com.pem (5120 bytes)

$ cfctl --org acme events list --kind cert.renewal_failed --kind deploy.failed --since 2026-10-01T00:00:00Z

$ cfctl keys status
FIELD            VALUE
kekId            static-...
kind             static
canaryOk         true
rewrapRunning    false
rewrapRemaining  -

$ cfctl backup create --out /var/backups/certforge/manual.cfbak
backup written to /var/backups/certforge/manual.cfbak (10485760 bytes)

$ cfctl --json audit list --action session.login --all
```

`--json` prints exactly what the server returned, unmodified, which suits `jq` or another script.

## Gaps

`cfctl` has no commands for enrolment approval, grants, organizations or agent CAs. Use the web UI or the [API](api.md).

## See also

- [API reference](api.md)
- [Server commands](server-cli.md)
- [Configuration reference](configuration.md#cfctl-environment-variables)
