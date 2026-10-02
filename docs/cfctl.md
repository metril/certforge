# cfctl

`cfctl` is a small operator CLI over CertForge's REST API: check server
status, list and act on certificates, clients, notification channels,
external monitors and events, read encryption key status or re-encrypt, take an on-demand
backup, and read the audit log — the same operations and authorization the
web UI uses, scriptable from a shell. It talks to a running server only
(see `operations.md#backup` for the offline `certforge backup`/`restore`
commands, which do not need one).

## Install

Each [release](https://github.com/metril/certforge/releases) attaches
static `cfctl_<version>_linux_<amd64|arm64>.tar.gz` tarballs and a
`SHA256SUMS` file:

```
curl -fsSLO https://github.com/metril/certforge/releases/download/<version>/cfctl_<version>_linux_amd64.tar.gz
curl -fsSLO https://github.com/metril/certforge/releases/download/<version>/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf cfctl_<version>_linux_amd64.tar.gz
sudo install -m 0755 cfctl /usr/local/bin/cfctl
```

`cfctl version` prints its own build version (`cfctl <version>`) — no
`--url`/`--token` needed.

## Config

`cfctl` needs a server URL and an API bearer token (Settings → API keys),
resolved in this order — the first source that supplies a value wins,
independently for the URL and the token:

1. Flags: `--url` and `--token`.
2. Environment: `CFCTL_URL` and `CFCTL_TOKEN`.
3. A config file at `$XDG_CONFIG_HOME/cfctl/config.json` (falling back to
   `~/.config/cfctl/config.json` when `XDG_CONFIG_HOME` is unset):

   ```json
   {"url": "https://certforge.example.com", "token": "cf_ap1_xxxxxxxx"}
   ```

The config file must be mode `0600` (`chmod 0600
~/.config/cfctl/config.json`) — `cfctl` refuses to read one that grants
any group or other permission bit, the same posture CertForge takes with
every other credential at rest.

**`--token` on the command line is visible to every other process on the
host** (`ps`, `/proc/<pid>/cmdline`, shell history). Prefer `CFCTL_TOKEN`
or the config file for anything beyond a one-off interactive command.

Other global flags: `--org <id|slug>` (the organization most commands
operate on — a plain UUID or a slug, resolved through `listOrgs`),
`--json` (print the server's raw JSON response instead of a table),
`--timeout <duration>` (per-request timeout, default 30s).

Exit codes: `0` success, `1` the server (or the request) failed — printed
as `error: <title>: <detail>` for an RFC 9457 problem response — `2` a
usage error (bad flags, an unknown command).

## Commands

```
cfctl status
cfctl certs list [--org] [--status] [--cursor] [--all]
cfctl certs get <id>
cfctl certs renew <id>
cfctl certs download <id> [--version] [--format pem|der] [--parts cert,chain,fullchain,key,combined] [--out <path|->]
cfctl clients list [--org] [--status] [--cursor] [--all]
cfctl clients get <id>
cfctl channels list
cfctl channels test <id>
cfctl monitors list
cfctl monitors check <id>
cfctl events list [--kind] [--severity] [--since] [--cursor] [--all]
cfctl keys status
cfctl keys rewrap
cfctl backup create --out <path|->
cfctl audit list [--action] [--cursor] [--all]
```

`--org` is required for `certs get/renew/download`, `clients get`,
`channels`, `monitors` and `events`; `certs list` and `clients list` fall
back to the cross-org "all orgs I can read" listing when it is omitted.
Every list command that paginates takes `--cursor` (continue from a
previous `nextCursor`) and `--all` (follow every page automatically, up
to 100 pages).

### Examples

```console
$ cfctl --org acme status
FIELD    VALUE
version  1.4.0

$ cfctl --org acme certs list --status active
ID                                    NAME        STATUS  NOT AFTER
5b1e...                               example.com active  2026-12-01T00:00:00Z

$ cfctl --org acme certs renew 5b1e...
enqueued=true

$ cfctl --org acme certs download 5b1e... --parts fullchain,key --out /etc/tls/example.com.pem

$ cfctl --org acme monitors check 9a2c...
ID       NAME  HOST              PORT  STATE
9a2c...  edge  edge.example.com  443   ok

$ cfctl keys status
FIELD            VALUE
kekId            static-...
kind             static
canaryOk         true
rewrapRunning    false
rewrapRemaining  -

$ cfctl backup create --out /var/backups/certforge/manual.cfbak
backup written to /var/backups/certforge/manual.cfbak (10485760 bytes)

$ cfctl audit list --action session.login --all --json
{"id":1234,"action":"session.login", ...}
```

`--json` prints exactly what the server returned (raw, unmodified, one
response body per page under `--all`) instead of a table — useful for
piping into `jq` or another script.
