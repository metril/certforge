import { expect, test, type APIRequestContext } from '@playwright/test';
import { adminApi } from './auth';
import { E2E } from './env';

let api: APIRequestContext;
let headers: Record<string, string>;
const auth = (enabled: boolean) => ({
  enabled, issuer: E2E.dexIssuer, clientId: 'certforge', clientSecret: enabled ? 'certforge-e2e-secret' : '__unchanged__',
  scopes: ['openid', 'profile', 'email'], groupsClaim: 'groups', sessionTtlHours: 12, trustedProxies: [],
});

test.beforeAll(async () => {
  ({ api, headers } = await adminApi());
  const res = await api.put('/api/v1/settings/authentication', { headers, data: auth(true) });
  expect(res.ok(), await res.text()).toBeTruthy();
});

test.afterAll(async () => {
  await api.put('/api/v1/settings/authentication', { headers, data: auth(false) });
  await api.dispose();
});

test('signs in through dex and gains the org once bound', async ({ page }) => {
  await page.goto('/login');
  await expect(page.getByRole('button', { name: 'Break-glass login' })).toBeVisible();
  await page.getByRole('link', { name: 'Sign in with single sign-on' }).click();
  await expect(page).toHaveURL(/^http:\/\/dex:5556\/dex\//);
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

  await page.goto('/');
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await expect(page.getByText('oidc-user').first()).toBeVisible();
  await page.goto(`/o/${E2E.orgSlug}/audit`);
  await expect(page.getByText("Your role can't read the audit log here.")).toBeVisible();
});
