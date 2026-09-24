# Changelog

All notable changes to CertForge are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Design specification, progress tracker, and repository scaffolding.
- Go module, certforge command skeleton, Makefile, golangci-lint config, CI workflow, development guide, ADRs 0001 and 0003.
- Bootstrap configuration from CF_* environment variables with KEK from env or file.
- Postgres pool, embedded goose migrations (orgs, sites, users, sessions, role bindings, settings, audit events), sqlc code generation, migrate command.
- Envelope encryption (AES-256-GCM DEK per secret, static KEK wrapper) with a compact blob format.
- Settings store with encrypted secrets, JSON-Schema-validated sections (general, backup), and KEK canary.
- Local admin argon2id passwords, Postgres-backed sessions, CSRF enforcement, and request principal middleware.
- Role-based authorization with org-scoped bindings (authz.Can).
