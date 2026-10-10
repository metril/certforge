# Upgrades

Upgrade the server first, then the agents. The server applies database migrations itself on start. This page lists the steps and the changes you must plan for.

## Before you start
- Read the release notes in `CHANGELOG.md` for every version between yours and the target.
- Keep a copy of the encryption key. A backup cannot be restored without it. See [Backup](../guide/backup.md).
- Take an on-demand backup first: **Settings → Backups → Back up now**, or `certforge backup --out file.cfbak`.

## Upgrade the server
1. Take a backup.
2. Pull the new image. With the release compose file, set the tag and recreate the server:

   ```sh
   CF_VERSION=<new version> docker compose -f deploy/compose.release.yaml up -d
   ```

3. Wait for `/readyz` to return `200`. See [Monitoring](monitoring.md#health-endpoints).
4. Check **Settings** and the **Overview** page for anything flagged.

`certforge serve` and `certforge migrate` apply embedded migrations on start. They are safe to run repeatedly and from several processes at once, because they take a database lock. There are no down migrations: to go back, restore the backup into a fresh database with the older version.

## Upgrade the agents
Agents are a separate binary and image (`certforge-agent`). Upgrade them after the server.

1. Pull the new agent image or replace the binary.
2. Restart the agent. It keeps its certificate, key and trust bundle in its data directory and reconnects without re-enrolling.
3. Check **Clients**: each upgraded client returns to **Online**.

## Breaking: the agent protocol changed
This applies when you upgrade from 0.8.0 or earlier to a release that includes the agent protocol through a proxy ([ADR 0020](../internals/adr/0020-agent-protocol-through-proxy.md)).

- **Old agents cannot talk to the new server**, and new agents cannot talk to an old server. The wire protocol is different: requests are signed, bodies are sealed, and the agent no longer authenticates with a TLS client certificate.
- **Order:** upgrade the server first, then every agent. Until an agent is upgraded, its client shows **Offline** and its deployments stop updating. Files already on the host keep working; nothing is removed.
- **Certificates stay valid.** Existing agent certificates, enrolled clients, grants and outstanding enrolment tokens keep working. Agents do not need to re-enrol.
- **New enrolments need approval by default.** **Settings → Agents → Require approval** (`agents.requireApproval`) is on. A new agent waits in **Awaiting approval** until an administrator compares its verification code and approves. Existing clients are not affected. Turn the setting off if you rely on unattended enrolment. See [Clients](../guide/clients.md#approval).
- **A TLS-terminating proxy now works.** If you routed agents around your proxy only because of mutual TLS, you can send them through it. See [Deploying](deploying.md#put-a-reverse-proxy-in-front) and [Agents](../guide/agents.md#behind-a-proxy).
- **Agent clocks must be within 60 s of the server.** Requests older or newer than that are refused. Enable NTP on agent hosts.
- **Port 8443 is optional.** Agents may use the HTTP port. Keep 8443 published if agents still connect to it.
- **Scripts that enrolled with a plain token body fail.** Only the shipped agent speaks the new enrolment exchange.

Roll back by restoring the backup and the old images together.

## Migrations
Migration `00005` reserves the organization slug `all` for the web UI's **All orgs** route. If an organization already has that slug, the migration stops before changing the schema:

```
org <id> has reserved slug "all"; rename it before this migration can run
```

Rename it and start the server again:

```sql
UPDATE orgs SET slug = '<new-slug>' WHERE id = '<id>';
```

## Common problems
**Agents show Offline after the server upgrade.** They still run the old protocol. Upgrade them.

**An upgraded agent logs `stale`.** Its clock is more than 60 s off. Fix the clock.

**An upgraded agent logs `ENROLMENT WAITING FOR APPROVAL`.** It is enrolling again and approval is on. Approve it under **Clients**, or check why it lost its data directory.

**The server does not start after the upgrade.** Read its log first. A wrong or missing encryption key stops it; see [Troubleshooting](troubleshooting.md#server).

## See also
- [Key management](key-management.md), [Backup](../guide/backup.md), [Deploying](deploying.md)
- [ADR 0020](../internals/adr/0020-agent-protocol-through-proxy.md)
