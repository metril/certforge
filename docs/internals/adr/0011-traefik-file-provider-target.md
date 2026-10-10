# 0011: Traefik through its file provider, rendered by shared code

Status: accepted (Phase 3)

## Context
Traefik is the reference agent-side deploy target. It can take certificates from ACME, a KV store, Kubernetes, or files. Drift detection needs the server to know the exact bytes the agent writes.

## Decision
- The agent writes PEM files and a dynamic-config YAML into Traefik's watched directory; no Docker socket, no API calls, no reload command.
- `internal/delivery` renders layouts and the Traefik files and is imported by both server and agent. The server computes each file's SHA-256 at the version's render time (`deployments.expected`); the agent writes exactly those bytes and reports their digests. The YAML is emitted by a small deterministic writer (no YAML dependency) and pinned by golden files.
- The bundle carries rendered layout files plus fullchain and key PEM for the target; the agent renders the target files itself with the same function.

## Consequences
Server and agent must run compatible `internal/delivery` versions: a rendering change shows up as drift until agents upgrade. Traefik on Kubernetes uses the Secret target in Phase 7 instead.
