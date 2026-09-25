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
};
