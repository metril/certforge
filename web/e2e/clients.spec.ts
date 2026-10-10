import { spawnSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { setTheme, snap } from './screens';

const PEM = `${E2E.certName}-pw.pem`;

test('clients: enrol the compose agent, grant a certificate, see it deployed', async ({ page }) => {
  test.setTimeout(300_000);
  await page.addInitScript(() => localStorage.setItem('cf-theme', 'light'));
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  // 1. The token embeds the agent URL, so point it at the Caddy proxy (the
  // agent reaches the server through a TLS-terminating hop) first.
  await page.goto('/settings/agents');
  await page.getByLabel('Agent URL').fill(E2E.agentUrl);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Settings saved')).toBeVisible();
  await expect(page.getByRole('list', { name: 'Listener names' })).toContainText('caddy');
  await snap(page, 'settings-agents');

  // 2. A layout writing the fullchain into the bind-mounted ssl directory.
  await page.goto(`/o/${E2E.orgSlug}/delivery/layouts`);
  await expect(page.getByRole('button', { name: 'New layout' }).first()).toBeVisible();
  await snap(page, 'layouts');
  await page.getByRole('button', { name: 'New layout' }).click();
  const layout = page.getByRole('dialog', { name: 'New layout' });
  await layout.getByLabel('Name', { exact: true }).fill('pw-files');
  const file = layout.getByRole('listitem', { name: 'File 1' });
  await file.getByLabel('Path', { exact: true }).fill(`/etc/ssl/certforge/${PEM}`);
  await file.getByRole('button', { name: /^Advanced/ }).click();
  await file.getByLabel('Mode', { exact: true }).fill('0644');
  await snap(page, 'layout-sheet');
  await layout.getByRole('button', { name: 'Save' }).click();
  await expect(layout).toBeHidden();

  // 3. Enrol: the compose agent waits for CF_AGENT_TOKEN_FILE=/data/token.
  await page.goto(`/o/${E2E.orgSlug}/clients`);
  await page.getByRole('link', { name: 'Enrol client' }).click();
  await page.getByLabel('Name', { exact: true }).fill('pw-agent');
  await page.getByRole('button', { name: 'Create token' }).click();
  const tokenRegion = page.getByRole('region', { name: 'Enrolment token' });
  const token = ((await tokenRegion.locator('code').first().textContent()) ?? '').trim();
  expect(token).toMatch(/^cf1\./);
  const connection = page.getByRole('region', { name: 'Agent connection' });
  await expect(connection).toContainText('Waiting for agent');
  await snap(page, 'enrol-waiting');
  await writeFile(resolve(E2E.agentDir, 'agent-data', 'token'), token, { mode: 0o600 });
  // The agent proves the token, then waits for an administrator.
  await expect(connection.getByText('Agent enrolled. Awaiting approval.')).toBeVisible({ timeout: 90_000 });
  await snap(page, 'enrol-awaiting');
  await expect(page.getByRole('link', { name: /^Clients, 1 awaiting approval/ })).toBeVisible();
  await connection.getByRole('button', { name: 'Review' }).click();
  const approve = page.getByRole('dialog', { name: /Approve agent/ });
  await expect(approve.getByTestId('verify-code')).toHaveText(/^[A-Z2-7]{4}-[A-Z2-7]{4}$/);
  // The code is also in the agent log; the two must match.
  const code = ((await approve.getByTestId('verify-code').textContent()) ?? '').trim();
  const compose = ['compose', '-p', 'certforge-e2e', '-f', resolve(E2E.agentDir, '..', 'deploy', 'compose.yaml'), '-f', resolve(E2E.agentDir, '..', 'deploy', 'compose.test.yaml')];
  const logs = spawnSync('docker', [...compose, '--profile', 'e2e', 'logs', 'agent'], { encoding: 'utf8' });
  expect(logs.status, logs.stderr).toBe(0);
  expect(logs.stdout + logs.stderr).toContain(code);
  // Approve stays blocked until the code is confirmed.
  const approveBtn = approve.getByRole('button', { name: 'Approve' });
  await expect(approveBtn).toHaveAttribute('aria-disabled', 'true');
  await snap(page, 'approve-dialog');
  await page.setViewportSize({ width: 375, height: 812 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  await setTheme(page, 'dark');
  await snap(page, 'approve-dialog-dark-375');
  await setTheme(page, 'light');
  await page.setViewportSize({ width: 1280, height: 720 });
  await approve.getByRole('switch', { name: /Code matches/ }).click();
  await expect(approveBtn).not.toHaveAttribute('aria-disabled', 'true');
  await approveBtn.click();
  await expect(approve).toBeHidden();
  await expect(page.getByRole('link', { name: /awaiting approval/ })).toBeHidden();
  await expect(connection.getByText('Online')).toBeVisible({ timeout: 90_000 });
  await snap(page, 'enrol-online');

  // 4. Grant the global-setup certificate with that layout.
  await connection.getByRole('link', { name: 'Grant certificate' }).click();
  const grant = page.getByRole('dialog', { name: 'Grant certificate' });
  await grant.getByRole('combobox', { name: 'Certificates' }).click();
  await page.getByRole('option', { name: new RegExp(`^${E2E.certName}`) }).click();
  await page.keyboard.press('Escape');
  await grant.getByRole('combobox', { name: 'Layout' }).click();
  await page.getByRole('option', { name: /^pw-files/ }).click();
  await grant.getByRole('button', { name: 'Grant' }).click();
  await expect(grant).toBeHidden();
  const grants = page.getByRole('table', { name: 'Grants' });
  await expect(grants.getByText('Deployed')).toBeVisible({ timeout: 90_000 });
  await grants.getByRole('button', { name: `Files for ${E2E.certName}` }).click();
  await expect(page.getByRole('list', { name: `Files for ${E2E.certName}` }).getByText('Match')).toBeVisible();
  await snap(page, 'client-certificates');
  expect(await readFile(resolve(E2E.agentDir, 'ssl', PEM), 'utf8')).toMatch(/^-----BEGIN CERTIFICATE-----/);

  // 5. The certificate's Deployments tab agrees.
  await page.goto(`/o/${E2E.orgSlug}/certificates`);
  await expect(page.getByRole('table', { name: 'Certificates' }).getByRole('link', { name: E2E.certName })).toBeVisible();
  await snap(page, 'certificates');
  await page.getByRole('table', { name: 'Certificates' }).getByRole('link', { name: E2E.certName }).click();
  await page.getByRole('tab', { name: 'Deployments' }).click();
  const deployments = page.getByRole('list', { name: 'Deployments' });
  await expect(deployments.getByRole('link', { name: 'pw-agent' })).toBeVisible();
  await expect(deployments.getByText('Deployed')).toBeVisible();
  await snap(page, 'certificate-deployments');

  // 6. Fleet list and Overview in both themes.
  await page.goto(`/o/${E2E.orgSlug}/clients`);
  await expect(page.getByRole('table', { name: 'Clients' }).getByText('Online')).toBeVisible();
  await snap(page, 'clients');
  await page.goto(`/o/${E2E.orgSlug}/overview`);
  await expect(page.getByRole('region', { name: 'Needs attention' })).toBeVisible();
  await snap(page, 'overview');
});

const READY: Record<string, RegExp> = {
  [`/o/${E2E.orgSlug}/clients`]: /^Clients$/,
  [`/o/${E2E.orgSlug}/clients/new`]: /^Enrol client$/,
  [`/o/${E2E.orgSlug}/delivery/targets`]: /^Delivery$/,
  [`/o/${E2E.orgSlug}/delivery/layouts`]: /^Delivery$/,
  [`/o/${E2E.orgSlug}/delivery/hooks`]: /^Delivery$/,
  '/settings/agents': /^Agents$/,
};

// Runs after the test above (workers: 1, file order), so pw-agent exists.
test('clients and delivery screens do not scroll sideways at 375 px', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.setViewportSize({ width: 375, height: 812 });
  for (const [path, heading] of Object.entries(READY)) {
    await page.goto(path);
    await expect(page.getByRole('heading', { name: heading })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth), path).toBeLessThanOrEqual(375);
  }
  await page.goto(`/o/${E2E.orgSlug}/clients`);
  await page.getByRole('link', { name: /pw-agent/ }).first().click();
  await expect(page.getByRole('heading', { name: 'pw-agent' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
});
