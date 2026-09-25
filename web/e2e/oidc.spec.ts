import type { APIRequestContext } from '@playwright/test';
import { adminApi, expect, test } from './auth';
import { E2E } from './env';

let api: APIRequestContext;
let headers: Record<string, string>;
let bindingId: string | undefined;
const auth = (enabled: boolean) => ({
  enabled, issuer: E2E.dexIssuer, clientId: 'certforge', clientSecret: enabled ? 'certforge-e2e-secret' : '__unchanged__',
  scopes: ['openid', 'profile', 'email'], groupsClaim: 'groups', sessionTtlHours: 12, trustedProxies: [],
});

// Matches E2E.dexIssuer's own scheme/host/path as a URL prefix, so this spec
// still points at wherever the issuer is actually configured instead of a
// literal copy of its default.
const dexIssuerPattern = new RegExp(`^${E2E.dexIssuer.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/`);

test.beforeAll(async () => {
  ({ api, headers } = await adminApi());
  const res = await api.put('/api/v1/settings/authentication', { headers, data: auth(true) });
  expect(res.ok(), await res.text()).toBeTruthy();
});

test.afterAll(async () => {
  // Delete the binding this test created so a rerun re-proves that binding
  // (not a leftover from a previous run) is what grants the org.
  if (bindingId) {
    const del = await api.delete(`/api/v1/role-bindings/${bindingId}`, { headers });
    expect(del.ok(), await del.text()).toBeTruthy();
  }
  const res = await api.put('/api/v1/settings/authentication', { headers, data: auth(false) });
  expect(res.ok(), await res.text()).toBeTruthy();
  await api.dispose();
});

test('signs in through dex and gains the org once bound', async ({ page }) => {
  await page.goto('/login');
  await expect(page.getByRole('button', { name: 'Break-glass login' })).toBeVisible();
  await page.getByRole('link', { name: 'Sign in with single sign-on' }).click();
  await expect(page).toHaveURL(dexIssuerPattern);
  await page.locator('#login').fill(E2E.oidcUser);
  await page.locator('#password').fill(E2E.oidcPassword);
  await page.locator('#submit-login').click();
  await expect(page).toHaveURL(/\/(no-organization|o\/[a-z0-9-]+\/overview)$/);

  const users = (await (await api.get('/api/v1/users')).json()) as { items: { id: string; email: string | null }[] };
  const user = users.items.find((u) => u.email === E2E.oidcUser);
  expect(user, 'dex user was not created').toBeTruthy();
  const orgs = (await (await api.get('/api/v1/orgs')).json()) as { items: { id: string; slug: string }[] };
  const org = orgs.items.find((o) => o.slug === E2E.orgSlug)!;

  const bind = await api.post('/api/v1/role-bindings', { headers, data: { subjectType: 'user', subject: user!.id, role: 'viewer', orgId: org.id } });
  expect([201, 409]).toContain(bind.status());
  if (bind.status() === 201) {
    bindingId = ((await bind.json()) as { id: string }).id;
  } else {
    // Already bound by a previous, unclean run: look the binding up instead
    // of skipping cleanup, so afterAll still deletes it.
    const existing = (await (await api.get(`/api/v1/role-bindings?orgId=${org.id}&subjectType=user`)).json()) as {
      items: { id: string; subject: string; role: string }[];
    };
    bindingId = existing.items.find((b) => b.subject === user!.id && b.role === 'viewer')?.id;
  }

  await page.goto('/');
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  // Stronger than a text match against the displayed name: confirm the
  // signed-in session (via page.request, so it carries the browser's own
  // session cookie) actually belongs to the dex user whose email the admin
  // API reported above — /auth/me's User has no email/subject of its own,
  // so the two are joined by id.
  const meRes = await page.request.get('/api/v1/auth/me');
  expect(meRes.ok(), await meRes.text()).toBeTruthy();
  const me = (await meRes.json()) as { user: { id: string; localAdmin: boolean } };
  expect(me.user.localAdmin).toBe(false);
  expect(me.user.id).toBe(user!.id);

  await page.goto(`/o/${E2E.orgSlug}/audit`);
  await expect(page.getByText("Your role can't read the audit log here.")).toBeVisible();
});
