# 0003. Use river for background jobs

Date: 2026-09-24. Status: accepted.

## Context
Issuance, renewal, polling, and notifications need durable jobs, uniqueness per certificate, cron, and retries with backoff.

## Decision
Use `github.com/riverqueue/river` on the existing Postgres. No Redis.

## Consequences
Jobs are transactional with domain writes and survive restarts. One more schema (river's own migrations) to manage. Throughput is bounded by Postgres, which is ample for a small team.
