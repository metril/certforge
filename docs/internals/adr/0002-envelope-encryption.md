# 0002. Envelope encryption for secrets and private keys

Date: 2026-09-24. Status: accepted.

## Context
Postgres holds ACME account keys, certificate private keys, DNS credentials, and other secrets. A database dump alone must not reveal them, and the KEK must be able to live outside the database (env, file, Vault Transit).

## Decision
Every secret gets a fresh 32-byte DEK and AES-256-GCM. The DEK is wrapped by a KEK through the `KeyWrapper` interface. One `bytea` column stores the version, KEK id, wrapped DEK, nonce, and ciphertext. The KEK id is bound as GCM additional data. A canary row (`settings` key `crypto.canary`) proves at startup that the configured KEK matches.

## Consequences
KEK rotation only rewraps DEKs (Phase 5). A wrong KEK is detected up front, and `/readyz` fails instead of requests failing randomly. Losing the KEK loses all secrets, so escrow is a documented operator duty.
