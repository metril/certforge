import { adminApi, expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { snap } from './screens';

test('flow: select the seeded certificate and see its issuer in the path panel', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Flow' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Flow' })).toBeVisible();
  for (const lane of ['Issuers', 'Certificates', 'Delivery', 'Clients', 'Alerts']) {
    await expect(page.getByRole('region', { name: lane })).toBeVisible();
  }
  await snap(page, 'flow');

  await page.getByRole('button', { name: new RegExp(`^Certificate ${E2E.certName},`) }).click();
  await expect(page).toHaveURL(/focus=certificate/);
  const panel = page.getByRole('complementary', { name: 'Details' });
  await expect(panel).toBeVisible();
  const issuerStep = panel.getByRole('listitem', { name: /^Issuer, 1 item/ });
  await expect(issuerStep).toBeVisible();
  await expect(issuerStep.getByRole('link', { name: /^Open / })).toBeVisible();
  await snap(page, 'flow-selected');

  // snap() toggles the theme, which moves focus out of the map; Escape only
  // clears the selection while focus is inside it.
  await page.getByRole('button', { name: new RegExp(`^Certificate ${E2E.certName},`) }).focus();
  await page.keyboard.press('Escape');
  await expect(panel).toHaveCount(0);
});

test('flow does not scroll sideways at 375 px', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(`/o/${E2E.orgSlug}/flow`);
  await expect(page.getByRole('heading', { level: 1, name: 'Flow' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  await page.getByRole('button', { name: new RegExp(`^Certificate ${E2E.certName},`) }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await snap(page, 'flow-mobile');
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
});

test('flow: filtering by the seeded certificate name keeps it visible', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.goto(`/o/${E2E.orgSlug}/flow`);
  await expect(page.getByRole('heading', { level: 1, name: 'Flow' })).toBeVisible();
  await page.getByRole('textbox', { name: 'Filter by name' }).fill(E2E.certName);
  await expect(page).toHaveURL(/q=/);
  await expect(page.getByRole('button', { name: new RegExp(`^Certificate ${E2E.certName},`) })).toBeVisible();
  await snap(page, 'flow-filtered');
});

test('flow: collapsing the Certificates lane leaves one proxy row and the connectors', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.goto(`/o/${E2E.orgSlug}/flow`);
  await expect(page.getByRole('heading', { level: 1, name: 'Flow' })).toBeVisible();
  await page.getByRole('region', { name: 'Certificates' }).getByRole('button', { name: /^Certificates/ }).click();
  await expect(page).toHaveURL(/collapsed=/);
  await expect(page.getByRole('button', { name: /^Expand Certificates,/ })).toBeVisible();
  await expect(page.getByRole('button', { name: new RegExp(`^Certificate ${E2E.certName},`) })).toHaveCount(0);
  await expect.poll(() => page.locator('[data-flow-connectors] path').count()).toBeGreaterThan(0);
  await snap(page, 'flow-collapsed');
});

test('flow: filter by client keeps only its path', async ({ page }) => {
  // Self-seeded: a pending client of its own, so the test does not depend on spec order.
  const name = `flow-filter-${Date.now()}`;
  const { api, headers } = await adminApi();
  const me = (await (await api.get('/api/v1/auth/me', { headers })).json()) as { orgs: { id: string; slug: string }[] };
  const orgId = me.orgs.find((o) => o.slug === E2E.orgSlug)?.id;
  if (!orgId) throw new Error(`org slug ${E2E.orgSlug} not found`);
  const created = await api.post(`/api/v1/orgs/${orgId}/clients`, { headers, data: { name } });
  if (!created.ok()) throw new Error(`create client: ${created.status()} ${await created.text()}`);
  const clientId = ((await created.json()) as { client: { id: string } }).client.id;
  try {
    await page.goto('/login');
    await signInLocal(page);
    await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
    await page.goto(`/o/${E2E.orgSlug}/flow`);
    await expect(page.getByRole('heading', { level: 1, name: 'Flow' })).toBeVisible();
    await page.getByRole('combobox', { name: 'Client' }).click();
    await page.getByRole('option', { name }).click();
    await expect(page).toHaveURL(/client=/);
    await page.keyboard.press('Escape');
    // Only the chosen client's lane entry and its path remain.
    await expect(page.getByRole('region', { name: 'Clients' }).locator('[data-flow-node]')).toHaveCount(1);
    await snap(page, 'flow-client-filter');
  } finally {
    await api.delete(`/api/v1/orgs/${orgId}/clients/${clientId}`, { headers });
    await api.dispose();
  }
});

test('flow: select the seeded certificate, Renew is offered and Open navigates to it', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.goto(`/o/${E2E.orgSlug}/flow`);
  await page.getByRole('button', { name: new RegExp(`^Certificate ${E2E.certName},`) }).click();
  const panel = page.getByRole('complementary', { name: 'Details' });
  await expect(panel.getByRole('button', { name: 'Renew' })).toBeVisible();
  await panel.getByRole('link', { name: `Open ${E2E.certName}` }).click();
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/certificates/`));
});

test('flow: an edge in the URL shows the Link panel', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.goto(`/o/${E2E.orgSlug}/flow`);
  await page.getByRole('button', { name: new RegExp(`^Certificate ${E2E.certName},`) }).click();
  const panel = page.getByRole('complementary', { name: 'Details' });
  await panel.getByRole('button', { name: /^→ / }).first().click();
  await expect(page).toHaveURL(/edge=/);
  await expect(panel.getByText('Link', { exact: true })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Clear' })).toBeVisible();
});
