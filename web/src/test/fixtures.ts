import { http, HttpResponse } from 'msw';
import type {
  AcmeAccount,
  ApiKey,
  Attempt,
  AuditEvent,
  CA,
  CAPreset,
  Certificate,
  Me,
  MeBinding,
  Org,
  ProviderSchema,
  RoleBinding,
  Site,
  UserDetail,
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
    verificationRules: [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }],
    overrides: {},
    status: 'active',
    currentVersion: {
      id: 'v-1',
      serial: '04ab19f2',
      notBefore: iso(-30),
      notAfter: iso(60),
      sha256Fingerprint: 'ab'.repeat(32),
      source: 'issued',
    },
    nextRenewAt: iso(30),
    failureCount: 0,
    effective: {},
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
export const ca: CA = { id: 'ca-1', name: "Let's Encrypt", preset: 'letsencrypt', directoryUrl: presets[0]!.directoryUrl, resolvers: [] };
export const account: AcmeAccount = { id: 'acc-1', caId: 'ca-1', email: 'ops@example.com', status: 'valid', registrationUri: 'https://acme-v02.api.letsencrypt.org/acme/acct/123456' };

// Provider schemas (Task 8). `secret`, `serverPath`, `unsupported`, and
// `unsupportedReason` are non-standard keywords the real provider JSON
// Schemas (internal/challenge/schemas/*.json) carry inside `schema`;
// ProviderSchema['schema'] is typed as a bag of unknown so they pass through
// untyped (preflight A10). route53 mirrors the real route53.json's
// server-managed AWS_SHARED_CREDENTIALS_FILE as a `serverPath` field, and
// hyperone mirrors the real hyperone.json's unsupported flag/reason, so
// SchemaForm/ProviderPicker tests exercise both against realistic shapes.
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
    required: ['CF_DNS_API_TOKEN'],
    properties: {
      CF_DNS_API_TOKEN: {
        type: 'string',
        title: 'CF_DNS_API_TOKEN',
        secret: true,
        description: 'API token with Zone.DNS edit rights (since v3.1.0). Create it under My Profile.',
      },
      CF_ZONE_API_TOKEN: { type: 'string', title: 'CF_ZONE_API_TOKEN', secret: true },
      CLOUDFLARE_TTL: { type: 'string', title: 'CLOUDFLARE_TTL', description: 'The TTL of the TXT record used for the DNS challenge in seconds (Default: 120)' },
      CLOUDFLARE_PROPAGATION_TIMEOUT: { type: 'string', title: 'CLOUDFLARE_PROPAGATION_TIMEOUT' },
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
