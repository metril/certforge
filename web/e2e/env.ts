export const E2E = {
  baseURL: process.env.CF_E2E_BASE_URL ?? `http://localhost:${process.env.CF_HTTP_PORT ?? '8080'}`,
  password: process.env.CF_E2E_ADMIN_PASSWORD ?? 'e2e-admin-password-1',
  orgSlug: process.env.CF_E2E_ORG ?? 'e2e',
  directoryUrl: process.env.CF_E2E_ACME_DIR ?? 'https://pebble:14000/dir',
  trustBundlePath: process.env.CF_E2E_TRUST_BUNDLE ?? '../test/e2e/testdata/pebble.minica.pem',
  resolvers: (process.env.CF_E2E_RESOLVERS ?? 'challtestsrv:8053').split(','),
  dnsProvider: process.env.CF_E2E_DNS_PROVIDER ?? 'e2e-challtestsrv',
  certName: 'smoke',
  commonName: 'smoke.example.test',
  dexIssuer: process.env.CF_E2E_DEX_ISSUER ?? 'http://dex:5556/dex',
  oidcUser: process.env.CF_E2E_OIDC_USER ?? 'oidc-user@example.test',
  oidcPassword: process.env.CF_E2E_OIDC_PASSWORD ?? 'password',
  // make e2e-web's bind-mount root (3A Task 15): agent-data/ holds the token
  // file the compose agent waits for, ssl/ is its /etc/ssl/certforge.
  agentDir: process.env.CF_E2E_AGENT_DIR ?? '../.e2e',
  // Where agents reach the server on the compose network.
  agentUrl: process.env.CF_E2E_AGENT_URL ?? 'https://caddy:9443',
  // 5B: Vault, always up in the compose `e2e` profile (Makefile's e2e-web
  // target exports both; pre-flight ruling: the Vault spec asserts
  // "Connected" unconditionally, not gated on these being set).
  vaultAddr: process.env.CF_E2E_VAULT_ADDR ?? 'http://vault:8200',
  vaultToken: process.env.CF_E2E_VAULT_TOKEN ?? 'certforge-e2e-root',
  // Task 9: the host-side webhook sink this suite starts itself (e2e/sink.ts),
  // reached by the compose server as http://host.docker.internal:<port>/hook
  // (deploy/compose.test.yaml's extra_hosts on the certforge service) — same
  // convention as test/e2e/ops_test.go's own opsWebhookSink/CF_E2E_SINK_PORT.
  sinkPort: Number(process.env.CF_E2E_SINK_PORT ?? '18090'),
  sinkHost: 'host.docker.internal',
  // mailpit's own HTTP API (published on the host), read back the same way
  // test/e2e/ops_test.go's opsMailpitMessages does.
  mailpitApi: `http://localhost:${process.env.CF_MAILPIT_PORT ?? '18025'}`,
};
