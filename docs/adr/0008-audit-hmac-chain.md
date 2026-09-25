# 0008: Keyed audit hash chain

Status: accepted (Phase 2)

## Context
Phase 1 linked audit rows with plain SHA-256. Anyone with write access to the table could rewrite the whole tail consistently.

## Decision
- Each row's hash is HMAC-SHA256 over (prev_hash, ts, actor, action, resource, org, ip, canonical details), keyed with `HKDF-SHA256(KEK, info "certforge-audit")`. `hash_alg` records the algorithm per row (`sha256` or `hmac-sha256`).
- At startup, after the KEK canary passes, `audit.Rechain` converts legacy rows once, inside one transaction under the append advisory lock. It first verifies every row with its stored algorithm and refuses (no change, error logged) if the legacy chain is already broken.
- `Rechain` does not disable the append-only trigger: table ownership (needed for `ALTER TABLE ... DISABLE TRIGGER`) conflicts with the planned non-owner application role. Instead, migration 00006 rewrites the trigger function itself to allow an `UPDATE` that changes only `hash`, `prev_hash` and `hash_alg` and leaves every other column (and `id`) unchanged; any other `UPDATE`, and every `DELETE`/`TRUNCATE`, is still rejected exactly as before. `Rechain`'s own `UpdateAuditChain` query only ever touches those three columns, so it needs no special privilege beyond ordinary `UPDATE` on them.
- Once no legacy row remains — because `Rechain` just converted the last of them, or because there never were any (a fresh install only ever writes HMAC rows) — `Rechain` persists a `audit.chain_keyed = true` marker in the `settings` table, in the same transaction as the re-chain commit. From then on, `Auditor.Check` rejects *any* row still stored under the legacy algorithm as broken, including one appended after the chain was keyed: a downgrade back to the unkeyed algorithm — whether from a bug or an attacker who can insert rows directly — is never accepted once the chain has been keyed, even if that row's own SHA-256 link would otherwise verify.
- `bootstrap-admin` runs the KEK canary (`Store.EnsureCanary`) before constructing its `Auditor`, and refuses outright on a wrong KEK, so it never writes rows keyed wrong.
- `GET /audit/verify` walks the chain (cached 60 s) and reports the first bad row.

## Consequences
Rewriting the chain now needs the KEK as well as table access. Starting the server with the wrong KEK skips re-chaining (readiness already fails in that state), but any event still recorded while running under the wrong KEK is keyed wrong and fails verification under the right one. KEK rotation (Phase 5) must re-derive the audit key and re-chain, or carry the old derived audit key forward. Still open: anchoring the head hash outside the table, and running the application under a role that does not own `audit_events`.
