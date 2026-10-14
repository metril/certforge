import { expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { pickTargetType } from './targetType';

// References between objects are links: a certificate's CA, a target's
// credential and, in the other direction, what a credential is used by.
test('entity links: certificate to CA, target to credential, credential back to target', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  // Certificate header -> its CA.
  await page.goto(`/o/${E2E.orgSlug}/certificates`);
  await page.getByRole('table', { name: 'Certificates' }).getByRole('link', { name: E2E.certName, exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: E2E.certName })).toBeVisible();
  await page.getByRole('main').locator('a[href*="/issuers/cas/"]').first().click();
  // A private CA has a detail page; any other kind opens its sheet on the list.
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/issuers/cas(/[^/?]+/overview|\\?edit=)`));
  await expect(page.getByRole('dialog').or(page.getByRole('heading', { level: 1 }))).toBeVisible();

  // A target that uses a saved credential.
  const suffix = Math.random().toString(36).slice(2, 8);
  const cred = `pw-link-cred-${suffix}`;
  const target = `pw-link-pf-${suffix}`;
  await page.goto(`/o/${E2E.orgSlug}/delivery/credentials`);
  await page.getByRole('button', { name: 'Add credential' }).first().click();
  const add = page.getByRole('dialog', { name: 'Add credential' });
  await add.getByLabel('Name', { exact: true }).fill(cred);
  await add.getByRole('radio', { name: 'Password' }).click();
  await add.getByLabel('Username', { exact: true }).fill('certforge');
  await add.getByLabel('Password', { exact: true }).fill('link-secret');
  await add.getByRole('button', { name: 'Save credential' }).click();
  await expect(add).toBeHidden();

  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  await page.getByRole('button', { name: 'Add target' }).first().click();
  const sheet = page.getByRole('main');
  await pickTargetType(sheet, /^pfSense Plus/);
  await sheet.getByLabel('Name', { exact: true }).fill(target);
  await sheet.getByLabel('API URL').fill('https://fw-link.example.net/api/v2');
  await sheet.getByRole('combobox', { name: 'Credential' }).click();
  await page.getByRole('option', { name: new RegExp(cred) }).click();
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet.getByRole('button', { name: 'Save' })).toBeHidden();

  // Target row -> its credential's sheet.
  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  const row = page.getByRole('table', { name: 'Deploy targets' }).getByRole('row', { name: new RegExp(`^${target}`) });
  await row.getByRole('link', { name: cred }).click();
  await expect(page).toHaveURL(/\/delivery\/credentials\?edit=/);
  const edit = page.getByRole('dialog', { name: `Edit ${cred}` });
  await expect(edit).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(edit).toBeHidden();

  // Credential's used-by popover -> the target.
  const credRow = page.getByRole('table', { name: 'Deploy credentials' }).getByRole('row', { name: new RegExp(cred) });
  await credRow.getByRole('button', { name: '1 target' }).click();
  await page.getByRole('link', { name: target, exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/delivery/targets/[^/]+/overview`));
});
