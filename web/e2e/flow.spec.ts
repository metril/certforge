import { expect, signInLocal, test } from './auth';
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
  const panel = page.getByRole('region', { name: 'Path' });
  await expect(panel).toBeVisible();
  await expect(panel.getByRole('heading', { name: 'Issuers' })).toBeVisible();
  await expect(panel.getByRole('link', { name: /^Open / }).first()).toBeVisible();
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
  await expect(page.getByRole('region', { name: 'Path' })).toBeVisible();
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
