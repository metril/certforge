import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { request, type APIResponse } from '@playwright/test';
import { E2E } from './env';

type Org = { id: string; slug: string };
type Cert = { id: string; name: string; status: string; lastError?: string };
type Me = { orgs: Org[]; csrfToken: string };

async function body<T>(res: Promise<APIResponse>): Promise<T> {
  const r = await res;
  if (!r.ok()) throw new Error(`${r.url()} → ${r.status()} ${await r.text()}`);
  return (r.status() === 204 ? undefined : await r.json()) as T;
}

export default async function globalSetup(): Promise<void> {
  const api = await request.newContext({ baseURL: E2E.baseURL, ignoreHTTPSErrors: true });
  try {
    const status = await body<{ needsSetup: boolean }>(api.get('/api/v1/setup/status'));

    // A fresh stack: setup/complete both creates the admin/org and logs the
    // admin in, returning Me (with csrfToken) directly. A stack setup already
    // ran against (e.g. a rerun) instead logs in — never both: setup/complete
    // sets the session cookie in this request context, and a follow-up POST
    // /auth/login with that cookie already present but no X-CSRF-Token gets
    // 403 from authn.Middleware.
    let me: Me;
    if (status.needsSetup) {
      me = await body<Me>(
        api.post('/api/v1/setup/complete', {
          data: { adminPassword: E2E.password, orgName: 'E2E', orgSlug: E2E.orgSlug, baseUrl: E2E.baseURL },
        }),
      );
    } else {
      await body(api.post('/api/v1/auth/login', { data: { password: E2E.password } }));
      me = await body<Me>(api.get('/api/v1/auth/me'));
    }

    const headers = { 'X-CSRF-Token': me.csrfToken };
    const org = me.orgs.find((o) => o.slug === E2E.orgSlug);
    if (!org) throw new Error(`org slug ${E2E.orgSlug} not found among ${me.orgs.map((o) => o.slug).join(', ') || '(none)'}`);
    const base = `/api/v1/orgs/${org.id}`;
    const find = async () =>
      (await body<{ items: Cert[] }>(api.get(`${base}/certificates?q=${E2E.certName}`))).items.find(
        (c) => c.name === E2E.certName,
      );

    if (!(await find())) {
      const trustBundlePem = await readFile(resolve(process.cwd(), E2E.trustBundlePath), 'utf8');
      const ca = await body<{ id: string }>(
        api.post(`${base}/cas`, {
          headers,
          data: { name: 'Pebble', preset: 'custom', directoryUrl: E2E.directoryUrl, trustBundlePem, resolvers: E2E.resolvers },
        }),
      );
      const account = await body<{ id: string }>(
        api.post(`${base}/acme-accounts`, { headers, data: { caId: ca.id, email: 'e2e@example.test' } }),
      );
      const cred = await body<{ id: string }>(
        api.post(`${base}/dns-credentials`, {
          headers,
          data: { name: 'challtestsrv', providerCode: E2E.dnsProvider, config: {} },
        }),
      );
      await body(
        api.post(`${base}/certificates`, {
          headers,
          data: {
            name: E2E.certName,
            commonName: E2E.commonName,
            sans: [E2E.commonName],
            verificationRules: [{ match: '*', method: 'dns-01', dnsCredentialId: cred.id }],
            overrides: { caId: ca.id, accountId: account.id },
          },
        }),
      );
    }

    const deadline = Date.now() + 120_000;
    for (;;) {
      const c = await find();
      if (c?.status === 'active') break;
      if (c?.status === 'failed') throw new Error(`certificate ${E2E.certName} failed: ${c.lastError ?? '(no error message)'}`);
      if (Date.now() > deadline) throw new Error(`certificate ${E2E.certName} not active: ${c?.status} ${c?.lastError ?? ''}`);
      await new Promise((r) => setTimeout(r, 2_000));
    }
  } finally {
    await api.dispose();
  }
}
