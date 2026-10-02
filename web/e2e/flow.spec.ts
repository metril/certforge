import { expect, signInLocal, test } from './auth';
import { E2E } from './env';

test('flow: select the seeded certificate and see its issuer in the path panel', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Flow' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Flow' })).toBeVisible();
  for (const lane of ['Issuers', 'Certificates', 'Delivery', 'Clients', 'Alerts']) {
    await expect(page.getByRole('region', { name: lane })).toBeVisible();
  }

  await page.getByRole('button', { name: new RegExp(`^Certificate ${E2E.certName},`) }).click();
  await expect(page).toHaveURL(/focus=certificate/);
  const panel = page.getByRole('region', { name: 'Path' });
  await expect(panel).toBeVisible();
  await expect(panel.getByRole('heading', { name: 'Issuers' })).toBeVisible();
  await expect(panel.getByRole('link', { name: /^Open / }).first()).toBeVisible();

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
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
});
