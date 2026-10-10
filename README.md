# CertForge

CertForge is a self-hosted certificate manager. It gets certificates from any ACME CA (Let's Encrypt, ZeroSSL, Google Trust Services, private ACME servers), from its own built-in private CA, or from Vault PKI. It stores the keys encrypted and delivers the certificates to the hosts that need them through a small agent. Everything is configured in a web UI; a CLI (`cfctl`) and a REST API cover automation.

The agent talks to the server over a signed and sealed channel. It works behind a TLS-terminating reverse proxy as well as on a direct connection.

## Quick start

You need Docker with Compose. Run these from a checkout of this repository:

```bash
mkdir -p deploy/secrets
head -c 32 /dev/urandom | base64 > deploy/secrets/kek   # the encryption key: back it up, it decrypts every secret
chown 65532 deploy/secrets/kek && chmod 0400 deploy/secrets/kek
docker compose -f deploy/compose.yaml up -d --build
curl -s localhost:8080/readyz
```

Open http://localhost:8080 and complete the setup wizard. Port 8080 serves the UI, the API and the agent protocol. Port 8443 is a second, optional agent listener; remove its mapping from the compose file if your agents connect through a reverse proxy.

New agents wait for an administrator to approve them (**Settings → Agents → Require approval** is on by default). See [Getting started](docs/guide/getting-started.md) for the full walk-through to your first certificate.

To run a published image instead of building, pin a version:

```bash
CF_VERSION=0.8.0 docker compose -f deploy/compose.release.yaml up -d
```

Images are `ghcr.io/metril/certforge` and `ghcr.io/metril/certforge-agent`. The [Releases page](https://github.com/metril/certforge/releases) has `certforge-agent` and `cfctl` binaries.

## Documentation

Start at the [documentation index](docs/README.md). It is grouped as:

- **Guide**: install, tour the UI, then one page per feature (certificates, issuers, challenges, clients, agents, delivery, alerts, access, Vault, backup, audit, settings).
- **Reference**: server and agent environment variables, `cfctl`, the `certforge` commands, the API, events, DNS providers.
- **Operations**: deploying behind a proxy, upgrades, monitoring, key management, the security model, troubleshooting.
- **Internals**: architecture, development, decision records, project history.

## License

TBD.
