import { http, HttpResponse } from 'msw';
import type { Certificate, Me, Org } from '@/api/types';

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
