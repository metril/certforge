# 0021: Per-grant target options

Status: accepted.

## Context
A Traefik target carried `defaultCert`, so every certificate granted to it was a candidate for the default certificate. Two grants on one client, directory and store then wrote conflicting `tls.stores.<store>.defaultCertificate` entries. The certificate directory was also fixed at `<dir>/certs/<name>`, so operators migrating from traefik-cert-watcher could not keep their existing layout.

## Decision
A grant carries `targetOptions`, validated by the target type's grant schema (`grantSchema`, served by `GET /meta/schemas`). Traefik's schema has `defaultCert`, `certsDir`, `certsDirTraefik` and `stores`. The server rejects a second default certificate for the same client, directory and store with 409, and rejects `targetOptions` on server-run targets.

The options travel to the agent as `Target.GrantOptions` in agentproto. The server (for drift comparison) and the agent (for writing) render files from the same parsed options, so both compute the same paths and content.

The target's `defaultCert` is removed. Migration 00026 adds `grants.target_options` and moves a target's `defaultCert` onto one grant per client: the certificate whose name sorts first, which is what Traefik was serving. Change it in the grant if another certificate should be the default.

## Consequences
- Breaking: the Traefik target no longer accepts `defaultCert`. A new agent cannot parse a stale target-level `defaultCert`, so upgrade the server before the agents.
- Agents that predate this change ignore `GrantOptions` and report drift on grants that use the options, until upgraded.
- Other target types can add their own grant schema without protocol changes.
- Operators can adopt CertForge beside traefik-cert-watcher and keep legacy paths with `certsDir`. See [Delivery](../../guide/delivery.md#replacing-traefik-cert-watcher).
