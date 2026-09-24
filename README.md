# CertForge

Self-hosted certificate manager. Obtains certificates from any ACME CA (Let's Encrypt, ZeroSSL, Buypass, Google Trust Services, private ACME servers) or a private CA, stores them encrypted, and distributes them to client agents over mTLS by push or pull. Configured entirely from a web UI. Optional HashiCorp Vault integration for key wrapping, secret sync, and PKI signing.

Status: in design and early implementation. See [docs/PROGRESS.md](docs/PROGRESS.md) for current state and [docs/design.md](docs/design.md) for the full design.

## Planned documentation

- `docs/architecture.md`, `docs/configuration.md`, `docs/certificates.md`, `docs/dns-providers.md`, `docs/agent.md`, `docs/deploy-targets.md`, `docs/notifications.md`, `docs/vault.md`, `docs/private-ca.md`, `docs/api.md`, `docs/security.md`, `docs/operations.md`, `docs/development.md`, `docs/adr/`.

## License

TBD.
