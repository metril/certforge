# Changelog

All notable changes to CertForge are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Design specification, progress tracker, and repository scaffolding.
- Go module, certforge command skeleton, Makefile, golangci-lint config, CI workflow, development guide, ADRs 0001 and 0003.
- Bootstrap configuration from CF_* environment variables with KEK from env or file.
- Postgres pool, embedded goose migrations (orgs, sites, users, sessions, role bindings, settings, audit events), sqlc code generation, migrate command.
