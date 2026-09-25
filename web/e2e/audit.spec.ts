import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import { signInLocal } from './auth';
import { E2E } from './env';

for (const theme of ['light', 'dark'] as const) {
  test(`audit log: events, chain, diff and CSV (${theme})`, async ({ page }) => {
    await page.addInitScript((t) => localStorage.setItem('cf-theme', t), theme);
    await page.goto('/login');
    await signInLocal(page);
    await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
    await expect(page.getByRole('region', { name: 'Recent activity' })).toBeVisible();

    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Audit log' }).click();
    const table = page.getByRole('table', { name: 'Audit events' });
    await expect(table.getByText('certificate.create').first()).toBeVisible();
    await expect(page.getByText('Chain verified')).toBeVisible();
    await page.screenshot({ path: `test-results/screens/${theme}-audit.png`, fullPage: true });

    await page.goto('/o/all/audit?action=session.');
    await expect(page.getByRole('status', { name: 'Read-only view' })).toBeVisible();
    await table.getByText('session.login').first().click();
    await expect(page.getByRole('dialog', { name: 'session.login' })).toBeVisible();
    await page.keyboard.press('Escape');

    const pending = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Export CSV' }).click();
    const download = await pending;
    expect(download.suggestedFilename()).toMatch(/^audit-\d{4}-\d{2}-\d{2}\.csv$/);
    const csv = await readFile((await download.path())!, 'utf8');
    expect(csv.split('\n')[0]).toBe('id,ts,actor_type,actor_id,actor_name,action,resource_type,resource_id,org_id,ip,details');
    expect(csv).toContain('session.login');
  });
}

test('new screens do not scroll sideways at 375 px', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.setViewportSize({ width: 375, height: 812 });
  for (const path of [`/o/${E2E.orgSlug}/audit`, '/settings/access?tab=users', '/settings/access?tab=bindings', '/settings/access?tab=keys', '/settings/authentication', '/settings/general']) {
    await page.goto(path);
    await page.waitForLoadState('networkidle');
    expect(await page.evaluate(() => document.documentElement.scrollWidth), path).toBeLessThanOrEqual(375);
  }
});
