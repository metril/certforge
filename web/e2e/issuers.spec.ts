import type { APIRequestContext } from '@playwright/test';
import { adminApi, expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { snap } from './screens';

type Org = { id: string; slug: string };
type Me = { orgs: Org[] };
type Cert = { id: string; name: string; status: string; lastError?: string };

async function body<T>(res: Promise<{ ok(): boolean; status(): number; text(): Promise<string>; json(): Promise<unknown> }>): Promise<T> {
  const r = await res;
  if (!r.ok()) throw new Error(`${r.status()} ${await r.text()}`);
  return (await r.json()) as T;
}

async function adminOrg(): Promise<{ api: APIRequestContext; headers: Record<string, string>; orgId: string }> {
  const { api, headers } = await adminApi();
  const me = await body<Me>(api.get('/api/v1/auth/me', { headers }));
  const org = me.orgs.find((o) => o.slug === E2E.orgSlug);
  if (!org) throw new Error(`org slug ${E2E.orgSlug} not found`);
  return { api, headers, orgId: org.id };
}

test('CA kind switching', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.goto(`/o/${E2E.orgSlug}/issuers/cas`);
  await page.getByRole('button', { name: 'Add CA' }).click();
  const sheet = page.getByRole('dialog', { name: 'Add certificate authority' });
  await expect(sheet).toBeVisible();

  // The sheet auto-focuses its first focusable element on open, which is
  // the Type field's own Help button (Field's `help="ca.type"`, before the
  // segmented control in DOM order) — its Tooltip opens on focus and, left
  // untouched, sits over the segmented control below it and swallows the
  // next click. Focusing the Name field first (needed anyway) moves focus
  // off it and closes that tooltip via blur.
  await sheet.getByLabel('Name', { exact: true }).click();

  // ACME -> Built-in CA -> Vault PKI -> Built-in CA, checking each body's
  // own first field along the way.
  await expect(sheet.getByText('Preset')).toBeVisible();
  await sheet.getByRole('radio', { name: 'Built-in CA' }).click();
  await expect(sheet.getByLabel('Common name')).toBeVisible();
  await sheet.getByRole('radio', { name: 'Vault PKI' }).click();
  await expect(sheet.getByLabel('Mount')).toBeVisible();
  await sheet.getByRole('radio', { name: 'Built-in CA' }).click();
  await expect(sheet.getByLabel('Common name')).toBeVisible();

  // Create the localca CA the rest of this test exercises.
  await sheet.getByLabel('Name', { exact: true }).fill('e2e-local');
  await sheet.getByLabel('Common name').fill('e2e-local');
  await sheet.getByRole('button', { name: 'Save CA' }).click();
  await expect(sheet).toBeHidden();

  const table = page.getByRole('table');
  const row = table.getByRole('row', { name: /^e2e-local/ });
  await expect(row).toBeVisible();
  await expect(row.getByText('Built-in CA')).toBeVisible();

  await page.getByRole('radiogroup', { name: 'Type' }).getByRole('radio', { name: 'Built-in CA' }).click();
  await expect(table.getByRole('row', { name: /^e2e-local/ })).toBeVisible();
  await expect(table.getByRole('row', { name: 'ACME' })).toHaveCount(0);

  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await table.getByRole('row', { name: /^e2e-local/ }).click();
  const detail = page.getByRole('dialog', { name: 'e2e-local' });
  await expect(detail).toBeVisible();
  // Batch 4 review: the detail sheet's own plain-text expiry line only
  // renders when ValidityBar can't (missing dates), so this now matches
  // exactly one element — ValidityBar's own "full" legend.
  await expect(detail.getByText(/Expires/)).toBeVisible();

  const dl = page.waitForEvent('download');
  await detail.getByRole('button', { name: 'Download', exact: true }).click();
  const download = await dl;
  expect(download.suggestedFilename()).toMatch(/-ca\.pem$/);

  const crlValue = (await detail.locator('code').first().textContent())?.trim() ?? '';
  expect(crlValue).toContain('/crl/');
  await detail.getByRole('button', { name: 'Copy CRL URL' }).click();
  await expect(async () => {
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(crlValue);
  }).toPass({ timeout: 5_000 });

  await detail.getByRole('button', { name: 'Rotate issuing certificate' }).click();
  const confirmDialog = page.getByRole('dialog', { name: 'Rotate issuing certificate?' });
  await confirmDialog.getByRole('textbox').fill('Rotate');
  await confirmDialog.getByRole('button', { name: 'Rotate' }).click();
  await expect(confirmDialog).toBeHidden();
  await expect(detail.getByText('Retired issuers')).toBeVisible({ timeout: 30_000 });
  await expect(detail.getByRole('button', { name: /^[0-9a-fA-F]{8} until /i })).toHaveCount(1);
  await snap(page, 'ca-detail');
});

test('server grant', async ({ page }) => {
  test.setTimeout(180_000);

  // Self-contained (pre-flight ruling: no order across files, or within
  // this file): its own Vault settings and its own localca certificate,
  // set up through the admin API before the page ever signs in — a session
  // login here would otherwise revoke the page's own session below (every
  // sign-in revokes that account's other sessions, auth.ts).
  const { api, headers, orgId } = await adminOrg();
  await body(api.put('/api/v1/settings/vault', { headers, data: { address: E2E.vaultAddr, authMethod: 'token', token: E2E.vaultToken } }));

  const ca = await body<{ id: string }>(
    api.post(`/api/v1/orgs/${orgId}/cas`, {
      headers,
      data: { name: 'e2e-server-grant-ca', type: 'localca', config: { subject: { commonName: 'e2e server grant root' } } },
    }),
  );
  let cert = await body<Cert>(
    api.post(`/api/v1/orgs/${orgId}/certificates`, {
      headers,
      data: { name: 'e2e-server-grant-cert', commonName: 'server-grant.e2e.test', overrides: { caId: ca.id } },
    }),
  );
  const certPath = `/api/v1/orgs/${orgId}/certificates/${cert.id}`;
  const deadline = Date.now() + 60_000;
  while (cert.status !== 'active') {
    if (Date.now() > deadline) throw new Error(`certificate not active: ${cert.status} ${cert.lastError ?? ''}`);
    await new Promise((r) => setTimeout(r, 1_000));
    cert = await body<Cert>(api.get(certPath, { headers }));
  }
  await api.dispose();

  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  await page.getByRole('button', { name: 'Add target' }).click();
  const targetSheet = page.getByRole('dialog', { name: 'Add deploy target' });
  await targetSheet.getByLabel('Name', { exact: true }).fill('e2e-vault-kv');
  await targetSheet.getByRole('radio', { name: 'Vault KV (runs on server)' }).click();
  await targetSheet.getByRole('button', { name: 'Save' }).click();
  await expect(targetSheet).toBeHidden();

  const targetsTable = page.getByRole('table', { name: 'Deploy targets' });
  const targetRow = targetsTable.getByRole('row', { name: /^e2e-vault-kv/ });
  await expect(targetRow).toBeVisible();
  await targetRow.getByRole('button', { name: 'Grants e2e-vault-kv' }).click();

  const targetDetail = page.getByRole('dialog', { name: 'e2e-vault-kv' });
  await expect(targetDetail).toBeVisible();
  await targetDetail.getByRole('button', { name: 'New server grant' }).click();
  await targetDetail.getByRole('combobox', { name: 'Certificate' }).click();
  await page.getByRole('option', { name: /^e2e-server-grant-cert/ }).click();
  await targetDetail.getByRole('button', { name: 'Grant' }).click();

  // Desktop viewport (playwright.config.ts): the table variant, not the
  // below-md card list.
  const grantsTable = targetDetail.getByRole('table', { name: 'Grants' });
  await expect(grantsTable.getByText(/^(Pending|Deployed|Failed)$/)).toBeVisible({ timeout: 60_000 });
  await snap(page, 'target-grants');

  await targetDetail.getByRole('button', { name: 'Redeploy e2e-server-grant-cert' }).click();
  await expect(page.getByText('Redeploy queued')).toBeVisible();
});

// Runs after the two tests above (workers: 1, file order — same convention
// as clients.spec.ts's own 375 px test): 'e2e-local' and 'e2e-vault-kv'
// already exist.
test('issuers, delivery and vault settings screens do not scroll sideways at 375 px', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.setViewportSize({ width: 375, height: 812 });
  const noScroll = async () => expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);

  await page.goto(`/o/${E2E.orgSlug}/issuers/cas`);
  await expect(page.getByRole('heading', { level: 1, name: 'Issuers' })).toBeVisible();
  await noScroll();
  await page.getByRole('table').getByRole('row', { name: /^e2e-local/ }).click();
  await expect(page.getByRole('dialog', { name: 'e2e-local' })).toBeVisible();
  await noScroll();
  await page.keyboard.press('Escape');

  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  await noScroll();
  await page.getByRole('table', { name: 'Deploy targets' }).getByRole('row', { name: /^e2e-vault-kv/ }).getByRole('button', { name: 'Grants e2e-vault-kv' }).click();
  await expect(page.getByRole('dialog', { name: 'e2e-vault-kv' })).toBeVisible();
  await noScroll();
  await page.keyboard.press('Escape');

  await page.goto('/settings/integrations');
  await expect(page.getByRole('heading', { level: 1, name: 'Settings' })).toBeVisible();
  await noScroll();

  await page.goto('/settings/backup');
  await noScroll();
});
