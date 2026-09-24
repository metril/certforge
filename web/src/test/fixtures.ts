import { http, HttpResponse } from 'msw';
import type { AcmeAccount, CA, CAPreset, Certificate, Me, Org } from '@/api/types';

export const url = (path: string) => `*/api/v1${path}`;
export const DAY = 86_400_000;
export const NOW = Date.parse('2026-09-24T12:00:00Z');
export const iso = (days: number) => new Date(NOW + days * DAY).toISOString();
export const PASSWORD = 'correct horse battery';

export const org: Org = { id: 'org-1', slug: 'acme', name: 'Acme' };
export const me: Me = { user: { id: 'u-1', displayName: 'admin', localAdmin: true }, roles: ['admin'], orgs: [org], csrfToken: 'csrf-1' };

export function makeCert(p: Partial<Certificate> = {}): Certificate {
  return {
    id: 'c-1',
    name: 'www',
    commonName: 'www.example.com',
    sans: ['www.example.com'],
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
