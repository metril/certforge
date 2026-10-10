import { expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { setTheme, snap } from './screens';

// The enrol, compare-code and approve path (waiting panel, nav badge, dialog,
// 375 px and dark checks) is exercised end to end in clients.spec.ts, which
// owns the one compose agent. A reject or expiry run needs a second agent
// identity, which the compose stack does not provide; the admin API and the
// rejected/expired protocol paths are covered by the Go integration tests and
// test/e2e/agent_test.go.

test('settings: the approval window greys out while approval is off', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.goto('/settings/agents');

  const require = page.getByRole('switch', { name: /Require approval/ });
  const window = page.getByLabel('Approval window (hours)');
  await expect(require).toBeChecked();
  await expect(window).toBeEnabled();
  await snap(page, 'settings-agents-approval');

  // Not saved: the compose agent still has to wait for an administrator.
  await require.click();
  await expect(window).toBeDisabled();
  await require.click();
  await expect(window).toBeEnabled();

  await page.setViewportSize({ width: 375, height: 812 });
  await setTheme(page, 'dark');
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  await snap(page, 'settings-agents-approval-dark-375');
});

test('clients: no queue and no badge when nothing awaits approval', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await page.goto(`/o/${E2E.orgSlug}/clients`);
  await expect(page.getByRole('heading', { name: /^Clients$/ })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Awaiting approval' })).toBeHidden();
  await expect(page.getByRole('link', { name: /awaiting approval/ })).toBeHidden();
});
