# CertForge documentation

## Guide

- [Getting started](guide/getting-started.md): install with Compose, set the encryption key, run the setup wizard, issue a first certificate.
- [Overview](guide/overview.md): the dashboard, Needs attention, Flow, the command palette, shortcuts and side panels.
- [Certificates](guide/certificates.md): issue, renew, revoke, import, download.
- [Issuers](guide/issuers.md): ACME CAs and accounts, the built-in private CA, Vault PKI.
- [Challenges](guide/challenges.md): DNS-01, HTTP-01, TLS-ALPN-01, manual DNS, CNAME delegation.
- [Clients](guide/clients.md): enrol hosts, approve or reject them, re-enrol, revoke.
- [Agents](guide/agents.md): run the agent, hooks, file layouts, pull mode, drift, running behind a proxy.
- [Delivery](guide/delivery.md): deploy targets, grants, secrets, redeploy.
- [Alerts](guide/alerts.md): notification channels, the events feed, external monitors.
- [Access](guide/access.md): organizations, users, roles, API keys, single sign-on.
- [Vault](guide/vault.md): Vault and OpenBao for the encryption key, KV delivery and PKI.
- [Backup](guide/backup.md): scheduled and on-demand backups, restore.
- [Audit log](guide/audit.md): who did what, filters, export, the tamper check.
- [Settings](guide/settings.md): a tour of every Settings section.

## Reference

- [Configuration](reference/configuration.md): server environment variables, the encryption key, every setting.
- [Agent](reference/agent.md): agent environment variables, subcommands, transport modes, limits.
- [cfctl](reference/cfctl.md): the command-line client.
- [Server commands](reference/server-cli.md): `certforge serve`, `migrate`, `bootstrap-admin`, `backup`, `restore`, `healthcheck`, `version`.
- [API](reference/api.md): authentication, pagination, errors; the full spec is `api/openapi.yaml`, served at `/api/docs/`.
- [Events](reference/events.md): event kinds, payloads, dedupe keys, webhook signatures.
- [DNS providers](reference/dns-providers.md): the generated provider catalogue.

## Operations

- [Deploying](operations/deploying.md): Compose files, ports, listeners, reverse proxies.
- [Upgrades](operations/upgrades.md): upgrade steps and breaking changes.
- [Monitoring](operations/monitoring.md): health endpoints, Prometheus, metrics.
- [Key management](operations/key-management.md): rotate the encryption key and the agent CA.
- [Security model](operations/security-model.md): trust boundaries and secrets at rest.
- [Troubleshooting](operations/troubleshooting.md): server-side problems.

## Internals

- [Architecture](internals/architecture.md): components, request path, agent protocol, data model.
- [Development](internals/development.md): build, test, end-to-end tests, code generation.
- [Architecture decision records](internals/adr/)
- [History](internals/history/PROGRESS.md): project progress log and design notes.
