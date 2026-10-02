import { readFile } from 'node:fs/promises';
import { expect, signInLocal, test } from './auth';
import { E2E } from './env';

for (const theme of ['light', 'dark'] as const) {
  test(`audit log: events, chain, diff and CSV (${theme})`, async ({ page }) => {
    await page.addInitScript((t) => localStorage.setItem('cf-theme', t), theme);
    await page.goto('/login');
    await signInLocal(page);
    await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
    await page.getByRole('tab', { name: 'Recent activity' }).click();
    await expect(page.getByRole('region', { name: 'Recent activity' })).toBeVisible();

    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Audit log' }).click();
    const table = page.getByRole('table', { name: 'Audit events' });
    await expect(table.getByText('certificate.create').first()).toBeVisible();
    await expect(page.getByText('Chain verified')).toBeVisible();
    await page.screenshot({ path: `test-results/screens/${theme}-audit.png`, fullPage: true });

    await page.goto('/o/all/audit');
    await expect(page.getByRole('status', { name: 'Read-only view' })).toBeVisible();

    // Drive the Action filter through the combobox itself, not the URL, so
    // this also exercises the control: picking the specific "session.login"
    // option (not the "session.*" group) must both surface a session.login
    // row and hide every certificate.create row.
    await page.getByRole('combobox', { name: 'Action' }).click();
    await page.getByRole('option', { name: 'session.login', exact: true }).click();
    await expect(table.getByText('session.login').first()).toBeVisible();
    await expect(table.getByText('certificate.create')).toHaveCount(0);

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

// Each path's own concrete, always-present heading — not `networkidle`,
// which can hang or under-wait depending on background polling (the audit
// chain check, Recent activity's refresh) that has nothing to do with these
// pages having actually finished rendering.
const READY_HEADING: Record<string, RegExp> = {
  [`/o/${E2E.orgSlug}/audit`]: /^Audit log$/,
  '/settings/access?tab=users': /^Access$/,
  '/settings/access?tab=bindings': /^Access$/,
  '/settings/access?tab=keys': /^Access$/,
  '/settings/authentication': /^Authentication$/,
  '/settings/general': /^General$/,
};

test('new screens do not scroll sideways at 375 px', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.setViewportSize({ width: 375, height: 812 });
  for (const [path, heading] of Object.entries(READY_HEADING)) {
    await page.goto(path);
    await expect(page.getByRole('heading', { name: heading })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth), path).toBeLessThanOrEqual(375);
  }
});
