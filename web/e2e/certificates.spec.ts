import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { snap } from './screens';

const fixture = (name: string) => resolve(process.cwd(), 'e2e/fixtures', name);

test('download PKCS#12', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Certificates' }).click();
  await page.getByRole('table', { name: 'Certificates' }).getByRole('link', { name: E2E.certName, exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: E2E.certName })).toBeVisible();

  await page.getByRole('button', { name: 'Download', exact: true }).click();
  const sheet = page.getByRole('dialog', { name: 'Download' });
  await sheet.getByRole('radiogroup', { name: 'Format' }).getByRole('radio', { name: 'PKCS#12' }).click();
  await expect(sheet.getByRole('button', { name: 'Download PKCS#12' })).toBeEnabled();
  await snap(page, 'download-p12');

  const dl = page.waitForEvent('download');
  await sheet.getByRole('button', { name: 'Download PKCS#12' }).click();
  const download = await dl;
  expect(download.suggestedFilename()).toBe(`${E2E.certName}.p12`);
  expect((await stat((await download.path())!)).size).toBeGreaterThan(0);
});

test('upload PEM', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.goto(`/o/${E2E.orgSlug}/certificates/upload`);
  await expect(page.getByRole('heading', { name: 'Upload certificate' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('pw-upload');
  const pem = await readFile(fixture('upload.pem'), 'utf8');
  await page.getByLabel('Certificate').fill(pem);
  await snap(page, 'upload');

  await page.getByRole('button', { name: 'Upload', exact: true }).click();
  await expect(page).toHaveURL(/\/certificates\/[^/]+\/overview$/);
  await expect(page.getByText('Managed externally')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Renew now' })).toBeDisabled();
  await snap(page, 'certificate-unmanaged');
});

test('import dry run', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.goto(`/o/${E2E.orgSlug}/certificates/import`);
  await expect(page.getByRole('heading', { name: 'Import certificates' })).toBeVisible();
  await page.getByLabel('Archive').setInputFiles(fixture('acmesh.zip'));
  await page.getByRole('combobox', { name: 'CA' }).click();
  await page.getByRole('option', { name: /^Pebble/ }).click();
  await page.getByRole('button', { name: 'Preview' }).click();

  const table = page.getByRole('table', { name: 'Import preview' });
  await expect(table).toBeVisible();
  await expect(table.getByText('Create').first()).toBeVisible();
  await snap(page, 'import-preview');
  // Do not click Import.
});

test('screens', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  // The wizard's Verification step with rule 1 set to HTTP.
  await page.goto(`/o/${E2E.orgSlug}/certificates/new`);
  await page.getByLabel('Names').fill('wizard-http.example.test');
  await page.getByLabel('Names').blur();
  await page.getByRole('button', { name: 'Next' }).click();
  await page.getByRole('radiogroup', { name: 'Rule 1 method' }).getByRole('radio', { name: 'HTTP' }).click();
  await snap(page, 'wizard-http01');

  // The New layout sheet with a PKCS#12 file.
  await page.goto(`/o/${E2E.orgSlug}/delivery/layouts`);
  await page.getByRole('button', { name: 'New layout' }).click();
  const layout = page.getByRole('dialog', { name: 'New layout' });
  await layout.getByLabel('Name', { exact: true }).fill('screens-p12');
  await layout.getByRole('radiogroup', { name: 'Format of file 1' }).getByRole('radio', { name: 'PKCS#12' }).click();
  await snap(page, 'layout-p12');
  await page.keyboard.press('Escape');
  await page.getByRole('dialog', { name: 'Discard changes?' }).getByRole('button', { name: 'Discard' }).click();

  // Settings → Issuance defaults, Global tab.
  await page.goto('/settings/issuance-defaults');
  await page.getByRole('tab', { name: 'Global' }).click();
  await expect(page.getByText('Checks and limits')).toBeVisible();
  await snap(page, 'settings-issuance');

  for (const section of ['general', 'authentication', 'access'] as const) {
    await page.goto(`/settings/${section}`);
    await expect(page.getByRole('heading', { level: 2, name: /^(General|Authentication|Access)$/ })).toBeVisible();
    await snap(page, `settings-${section}`);
  }
});

test('375 px: upload and import', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.setViewportSize({ width: 375, height: 812 });

  await page.goto(`/o/${E2E.orgSlug}/certificates/upload`);
  await expect(page.getByRole('heading', { name: 'Upload certificate' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);

  // Fix wave (Minor): the assertion used to run right after the bare form —
  // it never actually measured the widest thing this page renders, the
  // Import preview, which only exists once Preview has run. Below `md`
  // (D1) ImportPreview renders as cards inside a `<section
  // aria-label="Import preview">` (role "region"), not the desktop
  // `role="table"` `'import dry run'` asserts against — this is that
  // narrow layout, so a region is what's actually there.
  await page.goto(`/o/${E2E.orgSlug}/certificates/import`);
  await expect(page.getByRole('heading', { name: 'Import certificates' })).toBeVisible();
  await page.getByLabel('Archive').setInputFiles(fixture('acmesh.zip'));
  await page.getByRole('combobox', { name: 'CA' }).click();
  await page.getByRole('option', { name: /^Pebble/ }).click();
  await page.getByRole('button', { name: 'Preview' }).click();
  await expect(page.getByRole('region', { name: 'Import preview' }).getByText('Create').first()).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
});

// Fix wave: the 403 px single-column grid track this test used to hit
// (`document.documentElement.scrollWidth` measured 419) traced to `<Tabs>`
// (CertificateDetail.tsx) being a `min-width: auto` grid item while
// TabsList's five whitespace-nowrap triggers refuse to shrink below their
// combined min-content width (403 px) — nothing to do with the Download
// sheet itself, which is why the bare page below is checked too. Fixed by
// adding `min-w-0` to `<Tabs>`.
test('375 px: certificate detail, and with the Download sheet on PKCS#12', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.setViewportSize({ width: 375, height: 812 });

  // Below `md` the sidebar (nav "Main") is hidden behind the drawer's own
  // hamburger button; going straight to the list avoids that entirely,
  // matching clients.spec.ts's own 375 px test. Below `md` the list also
  // renders card rows (D9): the whole card is one `Link`, so its accessible
  // name is the name plus the status chip and validity text, not just the
  // name — match on a leading prefix instead of `exact`.
  await page.goto(`/o/${E2E.orgSlug}/certificates`);
  await page.getByRole('link', { name: new RegExp(`^${E2E.certName}`) }).click();
  await expect(page.getByRole('heading', { level: 1, name: E2E.certName })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);

  await page.getByRole('button', { name: 'Download', exact: true }).click();
  const sheet = page.getByRole('dialog', { name: 'Download' });
  await sheet.getByRole('radiogroup', { name: 'Format' }).getByRole('radio', { name: 'PKCS#12' }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
});
