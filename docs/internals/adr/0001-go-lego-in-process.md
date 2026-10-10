# 0001. Run ACME in-process with go-acme/lego

Date: 2026-09-24. Status: accepted.

## Context
CertForge must support any ACME CA, EAB, and roughly 150 DNS providers, and must route challenges per name.

## Decision
Use `github.com/go-acme/lego/v4` as a library inside the server, not certbot or acme.sh as subprocesses. Pin the lego version.

## Consequences
One language, typed errors, and ARI and EAB support. lego providers read credentials from env vars, so providers are built under a global mutex (set env, construct, restore), with a subprocess fallback. Provider form schemas are generated from lego's per-provider `.toml` files.
