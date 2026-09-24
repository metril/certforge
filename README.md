# CertForge

Self-hosted certificate manager. Obtains certificates from any ACME CA (Let's Encrypt, ZeroSSL, Buypass, Google Trust Services, private ACME servers) or a private CA, stores them encrypted, and distributes them to client agents over mTLS by push or pull. Configured entirely from a web UI. Optional HashiCorp Vault integration for key wrapping, secret sync, and PKI signing.

Status: early implementation. See [docs/PROGRESS.md](docs/PROGRESS.md) for current state and [the design spec](docs/design.md).

## Quick start

```bash
mkdir -p deploy/secrets
head -c 32 /dev/urandom | base64 > deploy/secrets/kek   # back this file up: it decrypts every key
chown 65532 deploy/secrets/kek && chmod 0400 deploy/secrets/kek   # container runs as uid 65532; see docs/configuration.md
docker compose -f deploy/compose.yaml up -d --build
curl -s localhost:8080/readyz
```

Open http://localhost:8080 and complete the setup wizard (or `POST /api/v1/setup/complete`). The API docs are at http://localhost:8080/api/docs/.

## Planned documentation

- `docs/architecture.md`, `docs/configuration.md`, `docs/certificates.md`, `docs/dns-providers.md`, `docs/agent.md`, `docs/deploy-targets.md`, `docs/notifications.md`, `docs/vault.md`, `docs/private-ca.md`, `docs/api.md`, `docs/security.md`, [`docs/operations.md`](docs/operations.md), `docs/development.md`, `docs/adr/`.

## License

TBD.
