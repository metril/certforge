import { http, HttpResponse } from 'msw';
import type {
  AcmeAccount,
  AgentCA,
  ApiKey,
  Attempt,
  AuditEvent,
  BackupStatus,
  CA,
  CAPreset,
  Certificate,
  CertificateVersion,
  Channel,
  Client,
  Deployment,
  DeployTarget,
  Grant,
  Hook,
  HookRun,
  ImportItem,
  ImportResult,
  KeysStatus,
  Layout,
  Me,
  MeBinding,
  Monitor,
  NotifyEvent,
  Org,
  ProviderSchema,
  RateLedger,
  RoleBinding,
  Site,
  UserDetail,
  VaultSettings,
} from '@/api/types';

export const url = (path: string) => `*/api/v1${path}`;
export const DAY = 86_400_000;
export const NOW = Date.parse('2026-09-24T12:00:00Z');
export const iso = (days: number) => new Date(NOW + days * DAY).toISOString();
export const PASSWORD = 'correct horse battery';

export const org: Org = { id: 'org-1', slug: 'acme', name: 'Acme' };
export const org2: Org = { id: 'org-2', slug: 'lab', name: 'Lab' };
export const me: Me = {
  user: { id: 'u-1', displayName: 'admin', localAdmin: true },
  roles: ['admin'],
  bindings: [{ role: 'admin', orgId: null }],
  orgs: [org],
  csrfToken: 'csrf-1',
};

export function meWith(bindings: MeBinding[], orgs: Org[] = [org]): Me {
  return { ...me, roles: [...new Set(bindings.map((b) => b.role))], bindings, orgs };
}

export const adminUser: UserDetail = {
  id: 'u-1', displayName: 'admin', email: null, localAdmin: true, oidcIssuer: null, oidcSubject: null,
  groups: [], disabled: false, lastLogin: iso(0), createdAt: iso(-30),
};
export const annUser: UserDetail = {
  id: 'u-2', displayName: 'Ann', email: 'ann@example.com', localAdmin: false, oidcIssuer: 'https://login.example.com',
  oidcSubject: 'ann', groups: ['ops', 'dev'], disabled: false, lastLogin: iso(-1), createdAt: iso(-10),
};

export function makeBinding(p: Partial<RoleBinding> = {}): RoleBinding {
  return { id: 'rb-1', subjectType: 'user', subject: 'u-2', subjectLabel: 'Ann', role: 'viewer', orgId: org.id, createdAt: iso(-1), ...p };
}

export function makeApiKey(p: Partial<ApiKey> = {}): ApiKey {
  return {
    id: 'k-1', name: 'ci', prefix: '0123456789ab', scopes: ['certs:read'], orgId: org.id, createdBy: 'u-1',
    createdByName: 'admin', expiresAt: iso(90), lastUsedAt: null, revokedAt: null, createdAt: iso(-1), ...p,
  };
}

export function makeAuditEvent(p: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: 1, ts: iso(0), actorType: 'user', actorId: 'u-1', actorName: 'admin', action: 'certificate.renew',
    resourceType: 'certificate', resourceId: 'c-1', orgId: org.id, ip: '192.0.2.10', details: {}, ...p,
  };
}

// Fix round 1 (review, Take now #3): later tasks (Orgs and sites) need a
// site fixture.
export function makeSite(p: Partial<Site> = {}): Site {
  return { id: 's-1', orgId: org.id, name: 'Primary', createdAt: iso(-1), ...p };
}

export function makeCert(p: Partial<Certificate> = {}): Certificate {
  return {
    id: 'c-1',
    name: 'www',
    commonName: 'www.example.com',
    // M1: the API returns `names[1:]` here (`names[0]` is always the common
    // name) — a certificate with no additional SANs has an empty `sans`,
    // not `[commonName]`.
    sans: [],
    verificationRules: [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1', via: 'server' }],
    overrides: {},
    status: 'active',
    managed: true,
    currentVersion: {
      id: 'v-1',
      serial: '04ab19f2',
      notBefore: iso(-30),
      notAfter: iso(60),
      sha256Fingerprint: 'ab'.repeat(32),
      source: 'issued',
      hasKey: true,
    },
    nextRenewAt: iso(30),
    failureCount: 0,
    effective: {},
    ariWindow: null,
    ...p,
  };
}

export function makeVersion(p: Partial<CertificateVersion> = {}): CertificateVersion {
  return {
    id: 'v-1',
    serial: '04ab19f2',
    notBefore: iso(-30),
    notAfter: iso(60),
    sha256Fingerprint: 'ab'.repeat(32),
    source: 'issued',
    hasKey: true,
    ...p,
  };
}

const problemHeaders = { 'Content-Type': 'application/problem+json' };
export const problem = (status: number, detail: string, headers: Record<string, string> = {}, title = 'Error') =>
  HttpResponse.json({ type: 'about:blank', title, status, detail }, { status, headers: { ...problemHeaders, ...headers } });
export const unauthorized = (detail = 'Sign in required.') => problem(401, detail);
// The exact title and detail internal/authn/middleware.go sends for a stale
// or missing CSRF token, so client.test.ts exercises the real wording.
export const csrfProblem = () =>
  problem(403, 'Send the csrfToken from GET /api/v1/auth/me in the X-CSRF-Token header.', {}, 'CSRF token missing or invalid');

export function authHandlers(state: { authed: boolean; needsSetup?: boolean }) {
  return [
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: state.needsSetup ?? false })),
    http.get(url('/auth/me'), () => (state.authed ? HttpResponse.json(me) : unauthorized())),
    http.post(url('/auth/login'), async ({ request }) => {
      const body = (await request.json()) as { password: string };
      if (body.password !== PASSWORD) return unauthorized('Wrong password.');
      state.authed = true;
      return HttpResponse.json(me);
    }),
    http.post(url('/auth/logout'), () => {
      state.authed = false;
      return new HttpResponse(null, { status: 204 });
    }),
  ];
}

// Adaptation (preflight A20; fix round 1 item 8): the real GET /meta/ca-presets
// returns 7 entries including `custom` (directoryUrl: ''), with names exactly
// as internal/signer/acme/presets.go defines them ("Let's Encrypt (staging)",
// "Custom directory") — appended after the three presets the brief specified
// so the existing index-based test references (presets[1], presets[2]) still
// point at letsencrypt-staging and zerossl.
export const presets: CAPreset[] = [
  { preset: 'letsencrypt', name: "Let's Encrypt", directoryUrl: 'https://acme-v02.api.letsencrypt.org/directory', requiresEab: false },
  { preset: 'letsencrypt-staging', name: "Let's Encrypt (staging)", directoryUrl: 'https://acme-staging-v02.api.letsencrypt.org/directory', requiresEab: false },
  { preset: 'zerossl', name: 'ZeroSSL', directoryUrl: 'https://acme.zerossl.com/v2/DV90', requiresEab: true },
  { preset: 'custom', name: 'Custom directory', directoryUrl: '', requiresEab: false },
];
export const ca: CA = {
  id: 'ca-1', orgId: org.id, name: "Let's Encrypt", preset: 'letsencrypt', directoryUrl: presets[0]!.directoryUrl, trustBundlePem: '',
  eabKid: '', hasEab: false, resolvers: [], shared: false, type: 'acme', config: {}, storedSecrets: [], createdAt: iso(-10), updatedAt: iso(-10),
};
export const account: AcmeAccount = { id: 'acc-1', caId: 'ca-1', email: 'ops@example.com', status: 'valid', registrationUri: 'https://acme-v02.api.letsencrypt.org/acme/acct/123456' };

// Phase 5B Task 1: private CAs (Deviations R4/R7), Vault settings and
// server-side grants. caLocal carries notBefore/notAfter/trustBundlePem
// (5a-facts.md: these are filled for both private kinds) and two retired
// issuing certificates, one without a crlUrl (a rotation from before
// general.baseUrl was set still has no published CRL for that issuer).
export const caLocal: CA = {
  id: 'ca-local-1',
  orgId: org.id,
  name: 'Internal CA',
  directoryUrl: '',
  trustBundlePem: '-----BEGIN CERTIFICATE-----\nMIIBROOTCA\n-----END CERTIFICATE-----\n',
  eabKid: '',
  hasEab: false,
  resolvers: [],
  shared: false,
  type: 'localca',
  config: {
    subject: { commonName: 'Internal CA', organization: 'Acme', country: 'US' },
    keyType: 'ec256',
    rootValidityYears: 10,
    issuingValidityYears: 3,
    maxLeafDays: 397,
    crl: true,
    imported: false,
    issuingPem: '-----BEGIN CERTIFICATE-----\nMIIBISSUING\n-----END CERTIFICATE-----\n',
    retired: [
      { pem: '-----BEGIN CERTIFICATE-----\nMIIBRETIRED1\n-----END CERTIFICATE-----\n', notAfter: iso(-10), serial: 'aa11bb22', crlUrl: 'https://certs.example.com/crl/ca-local-1/aa11bb22.crl' },
      { pem: '-----BEGIN CERTIFICATE-----\nMIIBRETIRED2\n-----END CERTIFICATE-----\n', notAfter: iso(-400), serial: 'cc33dd44' },
    ],
    revokedCount: 1,
  },
  storedSecrets: [],
  notBefore: iso(-30),
  notAfter: iso(1065),
  crlUrl: 'https://certs.example.com/crl/ca-local-1.crl',
  createdAt: iso(-30),
  updatedAt: iso(-1),
};

export const caLocalImported: CA = {
  ...caLocal,
  id: 'ca-local-2',
  name: 'Imported CA',
  config: { ...caLocal.config, imported: true, retired: [] },
  storedSecrets: ['importKeyPem'],
  notBefore: iso(-200),
  notAfter: iso(895),
  crlUrl: 'https://certs.example.com/crl/ca-local-2.crl',
  createdAt: iso(-200),
  updatedAt: iso(-200),
};

// Batch 1 review: a never-rotated Built-in CA has `retired: null` on the
// wire (Go's `Retired []retiredIssuer` has no `omitempty`, and create never
// sets it), not `[]` — every other localca fixture above happened to carry
// an array already.
export const caLocalNeverRotated: CA = {
  ...caLocal,
  id: 'ca-local-3',
  name: 'Never Rotated CA',
  config: { ...caLocal.config, retired: null },
  createdAt: iso(-1),
  updatedAt: iso(-1),
};

export const caVaultPki: CA = {
  id: 'ca-vault-1',
  orgId: org.id,
  name: 'Vault PKI',
  directoryUrl: '',
  trustBundlePem: '-----BEGIN CERTIFICATE-----\nMIIBVAULTCA\n-----END CERTIFICATE-----\n',
  eabKid: '',
  hasEab: false,
  resolvers: [],
  shared: false,
  type: 'vaultpki',
  config: { mount: 'pki', role: 'certforge', ttl: '2160h' },
  storedSecrets: [],
  notBefore: iso(-5),
  notAfter: iso(3645),
  createdAt: iso(-5),
  updatedAt: iso(-5),
};

export const keysStatic: KeysStatus = {
  kind: 'static',
  kekId: 'static-1',
  previous: [],
  canaryOk: true,
  rewrap: null,
};

export const keysRunning: KeysStatus = {
  kind: 'vault-transit',
  kekId: 'vault-transit-1',
  vaultAddress: 'https://vault.example.com:8200',
  previous: [{ kind: 'static', kekId: 'static-1' }],
  canaryOk: true,
  rewrap: {
    running: true,
    startedAt: iso(0),
    finishedAt: null,
    activeKekId: 'vault-transit-1',
    previousKekIds: ['static-1'],
    tables: [
      { table: 'settings', scanned: 10, rewrapped: 10, remaining: 0 },
      { table: 'cas', scanned: 4, rewrapped: 2, remaining: 2 },
      { table: 'acme_accounts', scanned: 0, rewrapped: 0, remaining: 3 },
      { table: 'dns_provider_credentials', scanned: 0, rewrapped: 0, remaining: 5 },
      { table: 'output_specs', scanned: 0, rewrapped: 0, remaining: 2 },
      { table: 'agent_cas', scanned: 0, rewrapped: 0, remaining: 1 },
      { table: 'certificate_versions', scanned: 0, rewrapped: 0, remaining: 12 },
    ],
    remaining: 25,
    error: null,
  },
};

export const keysDone: KeysStatus = {
  ...keysRunning,
  rewrap: {
    ...keysRunning.rewrap!,
    running: false,
    finishedAt: iso(0.02),
    tables: keysRunning.rewrap!.tables.map((t) => ({ ...t, scanned: t.scanned + t.remaining, rewrapped: t.scanned + t.remaining, remaining: 0 })),
    remaining: 0,
  },
};

export const vaultSettings: VaultSettings = {
  address: 'https://vault.example.com:8200',
  namespace: '',
  authMethod: 'token',
  timeoutSeconds: 10,
};

export const targetVaultKv: DeployTarget = {
  id: 't-vault-1',
  orgId: org.id,
  name: 'Vault KV',
  type: 'vault-kv',
  runsOn: 'server',
  config: {
    mount: 'secret',
    path: 'certforge/acme/www',
    keys: { fullchain: 'fullchain.pem', cert: 'cert.pem', chain: 'chain.pem', key: 'privkey.pem' },
    includeKey: false,
  },
  storedSecrets: [],
  grantCount: 1,
  createdAt: iso(-5),
  updatedAt: iso(-5),
};

// runsOn server: clientId/clientName/deployment are nullable and null here
// (5a-facts.md), serverDeployment carries the server-side deploy state.
export const grantServer: Grant = {
  id: 'g-server-1',
  clientId: null,
  clientName: null,
  certificateId: 'c-1',
  certificateName: 'www',
  delivery: 'push',
  layoutId: 'l-1',
  deployTargetId: targetVaultKv.id,
  hookIds: [],
  autoRemediate: false,
  deployment: null,
  runsOn: 'server',
  serverDeployment: { status: 'deployed', versionId: 'v-1', lastError: null, deployedAt: iso(-1), updatedAt: iso(-1) },
  createdAt: iso(-2),
  updatedAt: iso(-1),
};

// GET /meta/schemas' signers entries (Shared contracts "Meta"): localca's
// LocalCaConfig (importKeyPem is the secret field) and vaultpki's
// VaultPkiConfig. Mirrors internal/signer/localca/meta.go's ConfigSchema and
// internal/signer/vaultpki/meta.go's ConfigSchema verbatim (fix round: the
// original fixture approximated field titles/enums/constraints instead of
// copying the real Go JSON Schema literals).
export const metaSigners: ProviderSchema[] = [
  {
    code: 'localca',
    name: 'Private CA (built-in)',
    aliases: [],
    schema: {
      type: 'object',
      title: 'Private CA (built-in)',
      description:
        "CertForge's built-in root-plus-issuing-intermediate CA. Generates its own key material, or imports an operator-supplied issuing certificate and key.",
      additionalProperties: false,
      required: ['subject'],
      properties: {
        subject: {
          type: 'object',
          title: 'Subject',
          description: 'Root and issuing certificate subject. Immutable after create.',
          additionalProperties: false,
          required: ['commonName'],
          properties: {
            commonName: { type: 'string', minLength: 1, maxLength: 64, title: 'Common name' },
            organization: { type: 'string', maxLength: 64, title: 'Organization' },
            country: { type: 'string', pattern: '^[A-Z]{2}$', title: 'Country', description: 'ISO 3166-1 alpha-2 code.' },
          },
        },
        keyType: {
          type: 'string', enum: ['ec256', 'ec384', 'rsa2048', 'rsa4096'], default: 'ec256',
          title: 'Key type', description: 'Key algorithm for the root and issuing keys. Immutable after create.',
        },
        rootValidityYears: { type: 'integer', minimum: 1, maximum: 30, default: 10, title: 'Root validity (years)', description: 'Immutable after create.' },
        issuingValidityYears: { type: 'integer', minimum: 1, maximum: 10, default: 3, title: 'Issuing validity (years)', description: 'Immutable after create.' },
        maxLeafDays: {
          type: 'integer', minimum: 1, maximum: 825, default: 397,
          title: 'Max leaf validity (days)', description: 'Longest validity this CA will issue a leaf for. Editable after create.',
        },
        crl: { type: 'boolean', default: true, title: 'Publish CRL', description: 'Publish a CRL at GET /crl/{caId}.crl. Editable after create.' },
        importPem: {
          type: 'string', title: 'Import: certificate chain',
          description: 'Create only, immutable after: PEM to import instead of generating a root — the issuing certificate followed by its chain (the last certificate is the trust anchor).',
        },
        importKeyPem: {
          type: 'string', secret: true, title: 'Import: private key',
          description: "Create only, immutable after: PEM private key for importPem's issuing certificate. Never returned.",
        },
      },
    },
  },
  {
    code: 'vaultpki',
    name: 'Vault PKI',
    aliases: [],
    schema: {
      type: 'object',
      title: 'Vault PKI',
      description: "A private CA backed by Vault's (or OpenBao's) PKI secrets engine. Requires Settings → Integrations → Vault to be configured first.",
      additionalProperties: false,
      required: ['role'],
      properties: {
        mount: {
          type: 'string', pattern: '^[A-Za-z0-9_-][A-Za-z0-9_/-]{0,127}$', default: 'pki',
          title: 'Mount', description: 'Vault PKI secrets engine mount path.',
        },
        role: { type: 'string', minLength: 1, maxLength: 128, title: 'Role', description: 'Vault PKI role to sign leaves against.' },
        ttl: {
          type: 'string', title: 'TTL',
          description: "Go duration string for issued leaf validity, 1h to 19800h (825 days); Vault's own role or mount ceiling still applies.",
        },
      },
    },
  },
] as ProviderSchema[];

// Provider schemas (Task 8). `secret`, `serverPath`, `unsupported`, and
// `unsupportedReason` are non-standard keywords the real provider JSON
// Schemas (internal/challenge/schemas/*.json) carry inside `schema`;
// ProviderSchema['schema'] is typed as a bag of unknown so they pass through
// untyped (preflight A10). route53 mirrors the real route53.json's
// server-managed AWS_SHARED_CREDENTIALS_FILE as a `serverPath` field.
// hyperone below is a synthetic `unsupported` fixture kept only so
// ProviderPicker's unsupported-provider affordance still has something to
// render against; it no longer mirrors the real hyperone.json (5a-facts.md:
// hyperone is supported as of 5A Task 12, with an inline HYPERONE_PASSPORT
// secret field, the same file-backed shape transip already has — see
// `dns-providers.md#file-backed-credentials`).
// Fix round 1 (preflight A12): every real provider config property is
// `type: 'string'` (the API's DNSCredential.config is `{[key: string]: string}`);
// an `integer` field here (the original `ttl` fixture) is a shape the API
// never actually sends. Field names/titles mirror the real cloudflare.json.
export const cloudflare = {
  code: 'cloudflare',
  name: 'Cloudflare',
  aliases: ['cf'],
  schema: {
    type: 'object',
    additionalProperties: false,
    'x-auth-methods': [
      { id: 'api-token', label: 'API token', fields: ['CF_DNS_API_TOKEN'], optional: ['CF_ZONE_API_TOKEN'] },
      { id: 'email-api-key', label: 'Email + API key', fields: ['CF_API_EMAIL', 'CF_API_KEY'], optional: ['CF_ZONE_API_TOKEN'] },
    ],
    properties: {
      CF_API_EMAIL: { type: 'string', title: 'CF_API_EMAIL', 'x-group': 'credentials' },
      CF_API_KEY: { type: 'string', title: 'CF_API_KEY', secret: true, 'x-group': 'credentials' },
      CF_DNS_API_TOKEN: {
        type: 'string',
        title: 'CF_DNS_API_TOKEN',
        secret: true,
        'x-group': 'credentials',
        description: 'API token with Zone.DNS edit rights (since v3.1.0). Create it under My Profile.',
      },
      CF_ZONE_API_TOKEN: { type: 'string', title: 'CF_ZONE_API_TOKEN', secret: true, 'x-group': 'credentials' },
      CLOUDFLARE_API_KEY: { type: 'string', title: 'CLOUDFLARE_API_KEY', secret: true, 'x-group': 'credentials', 'x-alias-of': 'CF_API_KEY' },
      CLOUDFLARE_TTL: {
        type: 'string',
        title: 'CLOUDFLARE_TTL',
        'x-group': 'additional',
        description: 'The TTL of the TXT record used for the DNS challenge in seconds (Default: 120)',
      },
      CLOUDFLARE_PROPAGATION_TIMEOUT: { type: 'string', title: 'CLOUDFLARE_PROPAGATION_TIMEOUT', 'x-group': 'additional' },
    },
  },
} as ProviderSchema;
export const route53 = {
  code: 'route53',
  name: 'Amazon Route 53',
  aliases: ['aws', 'amazon'],
  schema: {
    type: 'object',
    required: ['accessKeyId', 'secretAccessKey'],
    properties: {
      accessKeyId: { type: 'string', title: 'Access key ID' },
      secretAccessKey: { type: 'string', title: 'Secret access key', secret: true },
      credentialsFile: { type: 'string', title: 'Credentials file', description: 'Managed by the AWS client.', serverPath: true },
    },
  },
} as ProviderSchema;
export const hetzner = { code: 'hetzner', name: 'Hetzner', aliases: [], schema: { type: 'object', properties: { apiKey: { type: 'string', title: 'API key', secret: true } } } } as ProviderSchema;
export const acmedns = { code: 'acme-dns', name: 'Joohoi ACME-DNS', aliases: ['acmedns'], schema: { type: 'object', properties: {} } } as ProviderSchema;
export const hyperone = {
  code: 'hyperone',
  name: 'HyperOne',
  aliases: [],
  schema: {
    type: 'object',
    unsupported: true,
    unsupportedReason: 'Requires a passport file; supported when file-backed credentials arrive in Phase 5.',
    properties: {},
  },
} as ProviderSchema;
export const providers: ProviderSchema[] = [acmedns, route53, cloudflare, hetzner, hyperone];

export function makeClient(p: Partial<Client> = {}): Client {
  return {
    id: 'cl-1', orgId: org.id, siteId: null, name: 'web-1', status: 'active', connected: true, online: true, hostname: 'web-1.lan',
    os: 'linux', arch: 'amd64', agentVersion: '0.3.0', capabilities: ['traefik', 'hooks'], lastSeen: iso(0),
    agentCertNotAfter: iso(60), agentCaId: 'aca-1', desiredRevision: 3, appliedRevision: 3, grantCount: 1, driftCount: 0, failedCount: 0,
    tokenExpiresAt: null, createdAt: iso(-10), ...p,
  };
}

export function makeDeployment(p: Partial<Deployment> = {}): Deployment {
  const f = { path: '/etc/ssl/www.pem', sha256: 'aa'.repeat(32) };
  return { state: 'ok', versionId: 'v-1', expected: [f], installed: [f], error: '', reportedAt: iso(0), updatedAt: iso(0), ...p };
}

export function makeGrant(p: Partial<Grant> = {}): Grant {
  return {
    id: 'g-1', clientId: 'cl-1', clientName: 'web-1', certificateId: 'c-1', certificateName: 'www', delivery: 'push',
    layoutId: 'l-1', deployTargetId: null, hookIds: [], autoRemediate: false, deployment: makeDeployment(),
    runsOn: 'agent', serverDeployment: null, createdAt: iso(-2), updatedAt: iso(-1), ...p,
  };
}

export function makeLayout(p: Partial<Layout> = {}): Layout {
  return {
    id: 'l-1', orgId: org.id, name: 'nginx', grantCount: 1, createdAt: iso(-5), updatedAt: iso(-5),
    passwordSet: false, extraCertificateIds: [],
    files: [{ path: '/etc/ssl/www.pem', format: 'pem', parts: ['fullchain'], owner: 'root', group: 'www-data', mode: '0640' }],
    ...p,
  };
}

export function makeTarget(p: Partial<DeployTarget> = {}): DeployTarget {
  return {
    id: 't-1', orgId: org.id, name: 'edge traefik', type: 'traefik', runsOn: 'agent', config: { dir: '/etc/traefik/dynamic' },
    storedSecrets: [], grantCount: 0, createdAt: iso(-5), updatedAt: iso(-5), ...p,
  };
}

// A server-run test-secret target with a stored `token`, for the
// stored-secret-with-schema-default and secret-leakage tests (task-1-brief.md,
// preflight ruling). `type: 'test-secret'` isn't in the real DeployTargetType
// enum (test-only, like testSecretSchema above), hence the cast rather than
// the `DeployTarget` annotation makeTarget's literals use.
export const targetTestSecret = {
  id: 't-test-secret-1',
  orgId: org.id,
  name: 'test sink',
  type: 'test-secret',
  runsOn: 'server',
  config: { url: 'https://sink.test' },
  storedSecrets: ['token'],
  grantCount: 0,
  createdAt: iso(-5),
  updatedAt: iso(-5),
} as unknown as DeployTarget;

export function makeHook(p: Partial<Hook> = {}): Hook {
  return {
    id: 'h-1', orgId: org.id, name: 'reload nginx', phase: 'post_deploy', argv: ['/usr/sbin/nginx', '-s', 'reload'],
    timeoutSeconds: 60, grantCount: 0, createdAt: iso(-5), updatedAt: iso(-5), ...p,
  };
}

export function makeHookRun(p: Partial<HookRun> = {}): HookRun {
  return {
    id: 'hr-1', grantId: 'g-1', hookId: 'h-1', hookName: 'reload nginx', phase: 'post_deploy',
    argv: ['/usr/sbin/nginx', '-s', 'reload'], exitCode: 0, durationMs: 120, stdout: '', stderr: '', ranAt: iso(0), ...p,
  };
}

export function makeAgentCA(p: Partial<AgentCA> = {}): AgentCA {
  return {
    id: 'aca-1', status: 'active', fingerprint: 'cd'.repeat(32), subject: 'CertForge agent CA', notBefore: iso(-100),
    notAfter: iso(3550), activeClientCerts: 2, createdAt: iso(-100), ...p,
  };
}

// Mirrors internal/delivery.TraefikSchema (plan 3A Task 6). runsOn/keyPolicy
// mirror internal/targets/traefik.go (7a-facts.md #2): agent-run, and
// keyPolicy always because it writes privkey.pem.
export const traefikSchema = {
  code: 'traefik',
  name: 'Traefik (file provider)',
  aliases: [],
  runsOn: 'agent',
  keyPolicy: 'always',
  schema: {
    type: 'object',
    additionalProperties: false,
    required: ['dir'],
    properties: {
      dir: { type: 'string', title: 'Directory on the agent', description: "Traefik's file-provider directory as the agent sees it.", pattern: '^/', examples: ['/etc/traefik/dynamic'] },
      pathPrefix: { type: 'string', title: 'Directory as Traefik sees it', description: 'Prefix for certFile and keyFile when Traefik mounts the directory elsewhere.', pattern: '^(/.*)?$' },
      defaultCert: { type: 'boolean', title: 'Default certificate', description: 'Also serve this certificate when no SNI matches.', default: false },
      stores: { type: 'array', title: 'TLS stores', description: 'Traefik TLS stores for the certificate. Empty means default.', items: { type: 'string', pattern: '^[A-Za-z0-9_-]{1,64}$' }, default: ['default'] },
      // Mirrors internal/delivery/traefik.go's TraefikSchema (4A Task 8: the
      // agent's http-01/tls-alpn-01 listener, routed to by a per-grant ACME
      // router file when set).
      acmeServiceUrl: {
        type: 'string',
        format: 'uri',
        title: 'ACME service URL',
        description:
          "Absolute http or https URL of the agent's http-01/tls-alpn-01 listener. When set, the agent also writes a per-grant certforge-acme-<name>.yml routing /.well-known/acme-challenge/ requests here.",
      },
    },
  },
} as ProviderSchema;

// Mirrors internal/deploy/vaultkv.go's vaultKVSchema verbatim (Task 8). The
// display name is bare now that RunsOnChip (7B, R12) carries "runs on
// server" instead of the name suffix. runsOn/keyPolicy mirror
// internal/deploy/vaultkv.go (7a-facts.md #2): server-run, keyPolicy
// optional (only needs the key when includeKey is set).
export const vaultKvSchema = {
  code: 'vault-kv',
  name: 'Vault KV',
  aliases: [],
  runsOn: 'server',
  keyPolicy: 'optional',
  schema: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: 'Vault KV',
    description:
      "Writes a certificate's files as one document in a Vault (or OpenBao) KV v2 secrets engine. Runs on the server; needs Settings → Integrations → Vault to be configured first.",
    type: 'object',
    additionalProperties: false,
    properties: {
      mount: {
        type: 'string', pattern: '^[A-Za-z0-9_-][A-Za-z0-9_/-]{0,127}$', default: 'secret',
        title: 'Mount', description: 'Vault KV v2 secrets engine mount path.',
      },
      path: {
        type: 'string', default: 'certforge/{org}/{name}',
        title: 'Path',
        description:
          'Secret path within the mount. May use {org} (org slug), {cert} (certificate id) and {name} (certificate name); no other placeholder is allowed. The rendered path must not start with / or contain ..',
      },
      keys: {
        type: 'object', additionalProperties: false,
        title: 'Document fields', description: 'KV document field name each PEM part is written under.',
        properties: {
          fullchain: { type: 'string', default: 'fullchain.pem', title: 'Fullchain field' },
          cert: { type: 'string', default: 'cert.pem', title: 'Certificate field' },
          chain: { type: 'string', default: 'chain.pem', title: 'Chain field' },
          key: { type: 'string', default: 'privkey.pem', title: 'Private key field' },
        },
      },
      includeKey: {
        type: 'boolean', default: false,
        title: 'Include private key', description: 'Also write the private key. A grant onto a target with this set needs keys:export.',
      },
    },
  },
} as ProviderSchema;

// Test-only fixture (task-1-brief.md): an `either`-runs-on, `always`-key-policy
// type with a secret field carrying a schema `default`, so tests can exercise
// the either-defaults-to-agent rule, the server-side keys:export gate and the
// stored-secret-default-overwrite guard (stripSecretDefaults) without relying
// on a shipped type. Never registered in the real product.
export const testSecretSchema = {
  code: 'test-secret',
  name: 'Test secret',
  aliases: [],
  runsOn: 'either',
  keyPolicy: 'always',
  schema: {
    type: 'object',
    properties: {
      url: { type: 'string', format: 'uri', title: 'URL' },
      token: { type: 'string', secret: true, default: 'default-token', title: 'Token' },
    },
  },
} as ProviderSchema;

export function makeAttempt(p: Partial<Attempt> = {}): Attempt {
  return {
    id: 'a-1',
    startedAt: iso(-0.01),
    finishedAt: iso(-0.009),
    outcome: 'failed',
    acmeErrorType: 'urn:ietf:params:acme:error:dns',
    retryAfter: iso(0.02),
    steps: [
      { name: 'account', status: 'success', startedAt: iso(-0.01), finishedAt: iso(-0.0099) },
      { name: 'order', status: 'success', startedAt: iso(-0.0099), finishedAt: iso(-0.0098) },
      { name: 'challenge www.example.com', status: 'failed', startedAt: iso(-0.0098), finishedAt: iso(-0.009), message: 'NXDOMAIN looking up TXT for _acme-challenge.www.example.com' },
    ],
    log: 'obtaining certificate\nrequesting order\npresenting dns-01 for www.example.com\nerror: NXDOMAIN looking up TXT',
    ...p,
  };
}

export function makeImportItem(p: Partial<ImportItem> = {}): ImportItem {
  return {
    name: 'www',
    names: ['www.example.com'],
    notAfter: iso(60),
    issuer: "Let's Encrypt",
    hasKey: true,
    source: 'acmesh',
    action: 'create',
    reason: 'new certificate',
    ...p,
  };
}

export function makeImportResult(p: Partial<ImportResult> = {}): ImportResult {
  return { dryRun: true, items: [makeImportItem()], ...p };
}

export function makeRateLedger(p: Partial<RateLedger> = {}): RateLedger {
  return {
    caId: ca.id,
    enforced: true,
    limits: { certsPerRegisteredDomainPerWeek: 50, duplicateCertsPerWeek: 5, failedValidationsPerHour: 5, newOrdersPer3Hours: 300 },
    items: [
      { limit: 'certsPerRegisteredDomainPerWeek', scope: 'example.com', count: 1, max: 50, windowSeconds: 604_800, resetsAt: iso(6) },
      { limit: 'duplicateCertsPerWeek', scope: 'www.example.com', count: 1, max: 5, windowSeconds: 604_800, resetsAt: iso(6) },
      { limit: 'failedValidationsPerHour', scope: 'example.com', count: 0, max: 5, windowSeconds: 3_600, resetsAt: null },
      { limit: 'newOrdersPer3Hours', scope: '', count: 1, max: 300, windowSeconds: 10_800, resetsAt: iso(0.1) },
    ],
    ...p,
  };
}

// Mirrors internal/issuance/issuance.schema.json (4A: the global "issuance"
// settings section — CAA checking and the local rate-limit ledger).
export const issuanceSettingsSchema = {
  title: 'Issuance',
  description: "Global CAA checking and a local record of the CA's own ACME rate limits, applied to every certificate.",
  type: 'object',
  additionalProperties: false,
  properties: {
    caaCheck: {
      type: 'boolean',
      title: 'Check CAA records',
      description: "Walk each name's CAA record set before ordering; fail fast when none authorizes the CA.",
      default: true,
    },
    rateLimits: {
      type: 'object',
      title: 'Rate limits',
      description: "Local tracking of the CA's own ACME rate limits, enforced before an order is placed. Set a limit to 0 to disable it.",
      additionalProperties: false,
      properties: {
        certsPerRegisteredDomainPerWeek: {
          type: 'integer', minimum: 0, maximum: 100_000,
          title: 'Certificates per registered domain per week',
          description: 'Counted per registered domain across every certificate. 0 disables the limit.',
          default: 50,
        },
        duplicateCertsPerWeek: {
          type: 'integer', minimum: 0, maximum: 100_000,
          title: 'Duplicate certificates per week',
          description: 'Counted per exact set of names. 0 disables the limit.',
          default: 5,
        },
        failedValidationsPerHour: {
          type: 'integer', minimum: 0, maximum: 100_000,
          title: 'Failed validations per hour',
          description: 'Counted per registered domain. 0 disables the limit.',
          default: 5,
        },
        newOrdersPer3Hours: {
          type: 'integer', minimum: 0, maximum: 100_000,
          title: 'New orders per 3 hours',
          description: 'Counted per CA account. 0 disables the limit.',
          default: 300,
        },
      },
    },
  },
};

// Phase 6B Task 1: channels, monitors, events, backup and the notifier meta
// schemas (mirrors internal/notify/{webhook,smtp.channel,discord,ntfy,homeassistant}.schema.json verbatim).
export function makeChannel(p: Partial<Channel> = {}): Channel {
  return {
    id: 'ch-1', orgId: org.id, name: 'ops-webhook', type: 'webhook', summary: 'hooks.example.com',
    config: {}, storedSecrets: ['url'], events: [], minSeverity: 'info', allOrgs: false, enabled: true,
    lastDelivery: null, createdAt: iso(-5), updatedAt: iso(-5), ...p,
  };
}

export function makeMonitor(p: Partial<Monitor> = {}): Monitor {
  return {
    id: 'mon-1', orgId: org.id, name: 'edge', host: 'edge.example.com', port: 443, sni: null,
    intervalSeconds: 3600, expectedCertificateId: null, expectedCertificateName: null, enabled: true,
    state: 'unknown', lastCheckedAt: null, nextCheckAt: iso(0), lastFingerprint: null, lastNotAfter: null,
    lastIssuer: null, lastError: null, createdAt: iso(-5), updatedAt: iso(-5), ...p,
  };
}

export function makeEvent(p: Partial<NotifyEvent> = {}): NotifyEvent {
  return {
    id: 'ev-1', kind: 'cert.expiring', at: iso(0), orgId: org.id, severity: 'warning',
    resource: { type: 'certificate', id: 'c-1', name: 'www' }, summary: 'www.example.com expires in 7 days',
    details: {}, deliveries: [], ...p,
  };
}

export const backupStatus: BackupStatus = {
  schedule: 'off', escrowConfirmed: false, directory: null, lastSuccessAt: null, lastFailureAt: null,
  lastError: null, lastSizeBytes: null, lastFile: null, nextAt: null,
};

export const smtpSettings = { host: 'smtp.example.com', port: 587, username: 'certforge', from: 'certforge@example.com', security: 'starttls', timeoutSeconds: 10 };
export const prometheusSettings = { enabled: true };
export const notificationsSettings = { allowLoopbackUrls: false, expiryWarningDays: 7, failureThreshold: 3 };

const webhookNotifierSchema = {
  title: 'Webhook',
  description: 'Sends the event as a JSON POST to any HTTP(S) endpoint, optionally HMAC-signed.',
  type: 'object',
  additionalProperties: false,
  required: ['url'],
  properties: {
    url: { type: 'string', title: 'URL', description: 'Endpoint CertForge sends the event to. Kept secret: a token embedded in the URL should not be exposed once saved.', maxLength: 2048, secret: true },
    authHeader: { type: 'string', title: 'Authorization header', description: 'Sent verbatim as the request’s Authorization header, for example "Bearer <token>".', maxLength: 1024, secret: true },
    headers: {
      type: 'object', title: 'Extra headers',
      description: 'Additional headers sent with every request. A credential-looking name (Authorization, Cookie, or one containing token, key, secret or auth) is rejected; use authHeader for a credential instead.',
      maxProperties: 20, additionalProperties: false,
      patternProperties: { '^[A-Za-z0-9-]{1,64}$': { type: 'string', maxLength: 1024 } },
    },
    signingSecret: { type: 'string', title: 'Signing secret', description: 'HMAC-SHA256 key for the X-CertForge-Signature header. Leave empty to send the request unsigned.', minLength: 16, maxLength: 256, secret: true },
    caPem: { type: 'string', title: 'CA certificate (PEM)', description: 'Additional trusted root certificate(s) for this endpoint, PEM-encoded.', maxLength: 65536 },
  },
};

const smtpNotifierSchema = {
  title: 'Email',
  description: 'Sends the event by email through the SMTP server configured in Settings.',
  type: 'object',
  additionalProperties: false,
  required: ['to'],
  properties: {
    to: { type: 'array', title: 'Recipients', description: 'Email addresses to send the notification to.', items: { type: 'string', format: 'email' }, minItems: 1, maxItems: 20, uniqueItems: true },
    subjectPrefix: { type: 'string', title: 'Subject prefix', description: "Prefix added to every notification email's subject.", maxLength: 64, default: '[CertForge]' },
  },
};

const discordNotifierSchema = {
  title: 'Discord',
  description: 'Posts the event as an embed through a Discord incoming webhook.',
  type: 'object',
  additionalProperties: false,
  required: ['webhookUrl'],
  properties: {
    webhookUrl: { type: 'string', title: 'Webhook URL', description: 'Discord incoming webhook URL (Server Settings -> Integrations -> Webhooks). Must be https.', maxLength: 2048, secret: true },
  },
};

const ntfyNotifierSchema = {
  title: 'ntfy',
  description: 'Publishes the event as a push notification through ntfy.sh or a self-hosted ntfy server.',
  type: 'object',
  additionalProperties: false,
  required: ['topic'],
  properties: {
    server: { type: 'string', title: 'Server', description: 'ntfy server base URL.', pattern: '^https?://[^/\\s]+(/.*)?$', maxLength: 2048, default: 'https://ntfy.sh' },
    topic: { type: 'string', title: 'Topic', description: 'ntfy topic to publish to.', pattern: '^[A-Za-z0-9_-]{1,64}$' },
    token: { type: 'string', title: 'Access token', description: 'ntfy access token, sent as a Bearer Authorization header. Leave empty for a public topic.', maxLength: 1024, secret: true },
    caPem: { type: 'string', title: 'CA certificate (PEM)', description: 'Additional trusted root certificate(s) for a self-hosted server, PEM-encoded.', maxLength: 65536 },
  },
};

const homeassistantNotifierSchema = {
  title: 'Home Assistant',
  description: 'Calls a Home Assistant webhook automation trigger with the event.',
  type: 'object',
  additionalProperties: false,
  required: ['baseUrl', 'webhookId'],
  properties: {
    baseUrl: { type: 'string', title: 'Base URL', description: 'Home Assistant base URL, for example https://homeassistant.local:8123.', pattern: '^https?://[^/\\s]+(/.*)?$', maxLength: 2048 },
    webhookId: { type: 'string', title: 'Webhook ID', description: "The webhook trigger's ID, as configured on the Home Assistant automation's Webhook trigger.", maxLength: 128, secret: true },
    caPem: { type: 'string', title: 'CA certificate (PEM)', description: 'Additional trusted root certificate(s), PEM-encoded.', maxLength: 65536 },
  },
};

export const metaNotifiers: ProviderSchema[] = [
  { code: 'webhook', name: 'Webhook', aliases: [], schema: webhookNotifierSchema },
  { code: 'smtp', name: 'Email', aliases: [], schema: smtpNotifierSchema },
  { code: 'discord', name: 'Discord', aliases: [], schema: discordNotifierSchema },
  { code: 'ntfy', name: 'ntfy', aliases: [], schema: ntfyNotifierSchema },
  { code: 'homeassistant', name: 'Home Assistant', aliases: [], schema: homeassistantNotifierSchema },
] as ProviderSchema[];
