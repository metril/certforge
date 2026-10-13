import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { snap } from './screens';
import { cancelSheet, expectRunsOn, pickTargetType } from './targetType';

// lib/help.ts's 'target.runsOnForced'/'target.runsOnLocked' text, copied
// rather than imported: that module reads `import.meta.env` (a Vite-only
// global), which doesn't exist under Playwright's own Node-based test runner
// (same convention as vault.spec.ts's own KEY_ROW_TOOLTIP).
const RUNS_ON_FORCED = 'This type can only run here.';
const fixture = (name: string) => resolve(process.cwd(), 'e2e/fixtures', name);
const CA_PEM = readFileSync(fixture('ca.pem'), 'utf8');
const CA_FP = 'E3:C1:98:FD:06:FA:9C:E9:DE:CE:2B:72:6B:97:5C:AA:6A:05:DF:5A:E0:61:28:60:36:E5:21:25:37:B0:5F:BF';

const RUNS_ON_LOCKED = 'Fixed once the target exists. Create a new target to change it.';

test('vault-kv sheet runs on server', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  await page.getByRole('button', { name: 'Add target' }).click();
  const sheet = page.getByRole('dialog', { name: 'Add deploy target' });
  await expect(sheet).toBeVisible();

  await pickTargetType(sheet, /^Vault KV/);
  await expectRunsOn(sheet, 'Server');

  // exact: true — the type segment's own accessible name ("Vault KV Server")
  // otherwise substring-matches the bare "Server"/"Agent" runs-on radios too.
  const runsOnServer = sheet.getByRole('radio', { name: 'Server', exact: true });
  await expect(runsOnServer).toHaveAttribute('aria-checked', 'true');
  const runsOnAgent = sheet.getByRole('radio', { name: 'Agent', exact: true });
  await expect(runsOnAgent).toBeDisabled();
  // scrollIntoViewIfNeeded first — it waits for the element to be stable,
  // which force: true's own hover otherwise skips; without it, a hover
  // fired while the sheet's 500ms slide-in (ui/sheet.tsx) is still in
  // progress computes an off-screen coordinate. force: true itself is
  // still needed for the hover — the disabled button has pointer-events:
  // none (native <button disabled>), which only force bypasses.
  await runsOnAgent.scrollIntoViewIfNeeded();
  await runsOnAgent.hover({ force: true });
  await expect(page.getByRole('tooltip')).toContainText(RUNS_ON_FORCED);

  // Admin has keys:export, so Include private key is not gated.
  await expect(sheet.getByRole('switch', { name: 'Include private key' })).toBeEnabled();

  await snap(page, 'target-sheet-vault-kv');

  // Cancel — nothing saved, so this test has no Vault dependency.
  await cancelSheet(sheet);
});

test('traefik target runs on agent', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  const name = `pw-traefik-${Math.random().toString(36).slice(2, 8)}`;

  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  await page.getByRole('button', { name: 'Add target' }).click();
  const sheet = page.getByRole('dialog', { name: 'Add deploy target' });
  await expect(sheet).toBeVisible();

  await pickTargetType(sheet, /^Traefik/);
  await expectRunsOn(sheet, 'Agent');
  // exact: true — the Vault KV type segment's own name ("Vault KV Server")
  // otherwise substring-matches the bare runs-on "Server" radio too.
  await expect(sheet.getByRole('radio', { name: 'Server', exact: true })).toBeDisabled();

  await sheet.getByLabel('Name', { exact: true }).fill(name);
  await sheet.getByLabel('Directory on the agent').fill('/etc/traefik/dynamic');
  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet).toBeHidden();

  const table = page.getByRole('table', { name: 'Deploy targets' });
  const row = table.getByRole('row', { name: new RegExp(`^${name}`) });
  await expect(row.getByText('Agent')).toBeVisible();
  await expect(row).toContainText('/etc/traefik/dynamic');
  // Agent-run targets have no Grants row action (that's server-run only).
  await expect(row.getByRole('button', { name: `Grants ${name}` })).toHaveCount(0);
  await snap(page, 'targets');

  await row.getByRole('button', { name: `Edit ${name}` }).click();
  const edit = page.getByRole('dialog', { name: `Edit ${name}` });
  await expect(edit).toBeVisible();
  // exact: true — the (still-rendered, locked) Traefik type segment's own
  // name ("Traefik Agent") otherwise substring-matches the bare runs-on
  // "Agent" radio too.
  const editAgent = edit.getByRole('radio', { name: 'Agent', exact: true });
  await expect(editAgent).toBeDisabled();
  // scrollIntoViewIfNeeded first — see the same-purpose comment above; this
  // is the site the coordinator's re-run actually caught the race on
  // ("Element is outside of the viewport" mid the sheet's slide-in).
  await editAgent.scrollIntoViewIfNeeded();
  await editAgent.hover({ force: true });
  await expect(page.getByRole('tooltip')).toContainText(RUNS_ON_LOCKED);
  await snap(page, 'target-sheet-traefik');
  await edit.getByRole('button', { name: 'Cancel' }).click();
  await expect(edit).toBeHidden();

  await row.getByRole('button', { name: `Delete ${name}` }).click();
  const confirm = page.getByRole('dialog', { name: 'Delete deploy target' });
  await confirm.getByLabel(name).fill(name);
  await confirm.getByRole('button', { name: 'Delete' }).click();
  await expect(confirm).toBeHidden();
  await expect(table.getByRole('row', { name: new RegExp(`^${name}`) })).toHaveCount(0);
});

test('targets at 375 px', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  // Self-contained (batch-2 review): seed our own target instead of relying
  // on issuers.spec.ts's own leftovers, so this test (and the file run
  // alone, e.g. --grep) never times out on an empty list.
  const name = `pw-mobile-${Math.random().toString(36).slice(2, 8)}`;
  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  await page.getByRole('button', { name: 'Add target' }).click();
  const addSheet = page.getByRole('dialog', { name: 'Add deploy target' });
  await pickTargetType(addSheet, /^Traefik/);
  await addSheet.getByLabel('Name', { exact: true }).fill(name);
  await addSheet.getByLabel('Directory on the agent').fill('/etc/traefik/dynamic');
  await addSheet.getByRole('button', { name: 'Save' }).click();
  await expect(addSheet).toBeHidden();

  await page.setViewportSize({ width: 375, height: 800 });
  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  const list = page.getByRole('list', { name: 'Deploy targets' });
  await expect(list).toBeVisible();
  expect(await page.evaluate(() => document.scrollingElement!.scrollWidth)).toBeLessThanOrEqual(375);

  await page.getByRole('button', { name: 'Add target' }).click();
  const sheet = page.getByRole('dialog', { name: 'Add deploy target' });
  await expect(sheet).toBeVisible();

  // With 7 types the Type field is a combobox (no per-segment chip); pick
  // one to check the open popover and chosen state still fit at 375px.
  await pickTargetType(sheet, /^Traefik/);
  await expectRunsOn(sheet, 'Agent');

  expect(await page.evaluate(() => document.scrollingElement!.scrollWidth)).toBeLessThanOrEqual(375);
  // batch-2 review: the sheet is a fixed, overflow-y-auto panel — content
  // too wide scrolls inside it and never widens the page, so the
  // document-level scrollWidth check above can't catch the sheet's own
  // overflow. Check the sheet's own box directly.
  expect(await sheet.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);

  await snap(page, 'targets-mobile');
  await cancelSheet(sheet);

  await list.getByRole('button', { name: `Delete ${name}` }).click();
  const confirm = page.getByRole('dialog', { name: 'Delete deploy target' });
  await confirm.getByLabel(name).fill(name);
  await confirm.getByRole('button', { name: 'Delete' }).click();
  await expect(confirm).toBeHidden();
});

test('saved credential: attach to two targets, rotate, delete blocked, detach, delete', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  const suffix = Math.random().toString(36).slice(2, 8);
  const cred = `pw-cred-${suffix}`;
  const targets = [`pw-pf-a-${suffix}`, `pw-pf-b-${suffix}`];

  // Create a password credential.
  await page.goto(`/o/${E2E.orgSlug}/delivery/credentials`);
  await page.getByRole('button', { name: 'Add credential' }).first().click();
  const add = page.getByRole('dialog', { name: 'Add credential' });
  await add.getByLabel('Name', { exact: true }).fill(cred);
  await add.getByRole('radio', { name: 'Password' }).click();
  await add.getByLabel('Username', { exact: true }).fill('certforge');
  await add.getByLabel('Password', { exact: true }).fill('first-secret');
  await snap(page, 'deploy-credential-sheet');
  await add.getByRole('button', { name: 'Save credential' }).click();
  await expect(add).toBeHidden();
  const credTable = page.getByRole('table', { name: 'Deploy credentials' });
  await expect(credTable.getByRole('row', { name: new RegExp(cred) })).toBeVisible();

  // Attach it to two pfSense targets; the login fields it supplies show
  // disabled with the credential's values.
  for (const [i, name] of targets.entries()) {
    await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
    await page.getByRole('button', { name: 'Add target' }).first().click();
    const sheet = page.getByRole('dialog', { name: 'Add deploy target' });
    await pickTargetType(sheet, /^pfSense Plus/);
    await sheet.getByLabel('Name', { exact: true }).fill(name);
    await sheet.getByLabel('API URL').fill(`https://fw${i}.example.net/api/v2`);
    await sheet.getByRole('combobox', { name: 'Credential' }).click();
    await page.getByRole('option', { name: new RegExp(cred) }).click();
    const username = sheet.getByLabel('Username', { exact: true });
    await expect(username).toBeDisabled();
    await expect(username).toHaveValue('certforge');
    await expect(sheet.getByLabel('Password', { exact: true })).toHaveCount(0);
    await expect(sheet.getByText('Stored', { exact: true })).toBeVisible();
    if (i === 0) await snap(page, 'target-sheet-credential');
    await sheet.getByRole('button', { name: 'Save' }).click();
    await expect(sheet).toBeHidden();
    await expect(page.getByRole('table', { name: 'Deploy targets' }).getByRole('row', { name: new RegExp(`^${name}`) })).toContainText(`uses ${cred}`);
  }

  // The detail sheet links to the credential.
  const targetsTable = page.getByRole('table', { name: 'Deploy targets' });
  await targetsTable.getByRole('button', { name: `Grants ${targets[0]}` }).click();
  const detail = page.getByRole('dialog', { name: new RegExp(targets[0]!) });
  await expect(detail.getByRole('link', { name: cred })).toBeVisible();
  await snap(page, 'target-detail-credential');
  await page.keyboard.press('Escape');
  await expect(detail).toBeHidden();

  // Rotate: replace the stored password.
  await page.goto(`/o/${E2E.orgSlug}/delivery/credentials`);
  const credRow = credTable.getByRole('row', { name: new RegExp(cred) });
  await expect(credRow).toContainText('2 targets');
  await credRow.getByRole('button', { name: `Edit ${cred}` }).click();
  const edit = page.getByRole('dialog', { name: `Edit ${cred}` });
  await edit.getByRole('button', { name: 'Replace Password' }).click();
  await edit.getByLabel('Password', { exact: true }).fill('second-secret');
  await edit.getByRole('button', { name: 'Save credential' }).click();
  await expect(edit).toBeHidden();

  // Delete is blocked while targets use it.
  const del = credRow.getByRole('button', { name: `Delete ${cred}` });
  await expect(del).toHaveAttribute('aria-disabled', 'true');
  await del.hover({ force: true });
  await expect(page.getByRole('tooltip')).toContainText('Used by 2 targets');
  await snap(page, 'deploy-credentials');

  // Detach both targets (enter the login by hand), then delete them.
  for (const name of targets) {
    await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
    await targetsTable.getByRole('button', { name: `Edit ${name}` }).click();
    const sheet = page.getByRole('dialog', { name: `Edit ${name}` });
    await sheet.getByRole('combobox', { name: 'Credential' }).click();
    await page.getByRole('option', { name: 'Enter manually' }).click();
    await sheet.getByLabel('Username', { exact: true }).fill('admin');
    await sheet.getByLabel('Password', { exact: true }).fill('own-secret');
    await sheet.getByRole('button', { name: 'Save' }).click();
    await expect(sheet).toBeHidden();
  }
  await page.goto(`/o/${E2E.orgSlug}/delivery/credentials`);
  await expect(credRow.getByText('2 targets')).toHaveCount(0);
  await credRow.getByRole('button', { name: `Delete ${cred}` }).click();
  const confirm = page.getByRole('dialog', { name: 'Delete credential' });
  await confirm.getByLabel(cred).fill(cred);
  await confirm.getByRole('button', { name: 'Delete credential' }).click();
  await expect(confirm).toBeHidden();
  await expect(credTable.getByRole('row', { name: new RegExp(cred) })).toHaveCount(0);

  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  for (const name of targets) {
    await targetsTable.getByRole('button', { name: `Delete ${name}` }).click();
    const c = page.getByRole('dialog', { name: 'Delete deploy target' });
    await c.getByLabel(name).fill(name);
    await c.getByRole('button', { name: 'Delete' }).click();
    await expect(c).toBeHidden();
  }
});

test('pfSense CA certificate: upload a DER file and fetch from the server', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  // The fetch is mocked: no https service in the e2e stack is reachable from
  // the server under the deploy-target address policy.
  const leafPem = '-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n';
  await page.route(/\/api\/v1\/orgs\/[^/]+\/tls\/peek$/, (route) =>
    route.fulfill({
      json: {
        ok: true,
        verified: false,
        chain: [
          { subject: 'CN=fw.example.net', issuer: 'CN=CertForge Test Root,O=CertForge Test', notBefore: '2026-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z', sha256: 'AA:BB:CC', isCa: false, selfSigned: false, pem: leafPem },
          { subject: 'CN=CertForge Test Root,O=CertForge Test', issuer: 'CN=CertForge Test Root,O=CertForge Test', notBefore: '2026-01-01T00:00:00Z', notAfter: '2126-01-01T00:00:00Z', sha256: CA_FP, isCa: true, selfSigned: true, pem: CA_PEM },
        ],
      },
    }),
  );

  const name = `pw-pfsense-ca-${Math.random().toString(36).slice(2, 8)}`;
  await page.setViewportSize({ width: 375, height: 800 });
  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  await page.getByRole('button', { name: 'Add target' }).first().click();
  const sheet = page.getByRole('dialog', { name: 'Add deploy target' });
  await pickTargetType(sheet, /^pfSense Plus/);
  await sheet.getByLabel('Name', { exact: true }).fill(name);
  await sheet.getByLabel('API URL').fill('https://fw.example.net/api/v2');
  await sheet.getByLabel('Username', { exact: true }).fill('admin');
  await sheet.getByLabel('Password', { exact: true }).fill('secret');

  // Upload: DER converts to PEM in the browser.
  const box = sheet.getByRole('textbox', { name: /CA certificate/ });
  await sheet.getByLabel('Upload CA certificate').setInputFiles(fixture('ca.der'));
  await expect(box).toHaveValue(CA_PEM);
  await expect(sheet.getByText('CertForge Test Root')).toBeVisible();

  // Fetch: the form URL prefills the server; the root is suggested and is
  // already present, so adding the leaf too appends only the leaf.
  await sheet.getByRole('button', { name: 'Fetch from server' }).click();
  const dialog = page.getByRole('dialog', { name: /Fetch from server/ });
  await expect(dialog.getByRole('textbox', { name: 'Server' })).toHaveValue('https://fw.example.net/api/v2');
  await dialog.getByRole('button', { name: 'Fetch', exact: true }).click();
  await expect(dialog.getByText(`SHA-256 ${CA_FP}`)).toBeVisible();
  await expect(dialog.getByRole('button', { name: /CertForge Test Root.*Self-signed/ })).toHaveAttribute('aria-pressed', 'true');
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  await snap(page, 'ca-bundle-fetch-375');
  await dialog.getByRole('button', { name: /fw\.example\.net/ }).click();
  await dialog.getByRole('button', { name: 'Add 2 certificates' }).click();
  await expect(dialog).toBeHidden();
  await expect(box).toHaveValue(CA_PEM + leafPem);
  await box.fill(CA_PEM);
  await page.setViewportSize({ width: 1280, height: 800 });

  await sheet.getByRole('button', { name: 'Save' }).click();
  await expect(sheet).toBeHidden();

  const table = page.getByRole('table', { name: 'Deploy targets' });
  await table.getByRole('button', { name: `Edit ${name}` }).click();
  const edit = page.getByRole('dialog', { name: `Edit ${name}` });
  await expect(edit.getByRole('textbox', { name: /CA certificate/ })).toHaveValue(CA_PEM.trimEnd());
  await cancelSheet(edit);

  await table.getByRole('button', { name: `Delete ${name}` }).click();
  const confirm = page.getByRole('dialog', { name: 'Delete deploy target' });
  await confirm.getByLabel(name).fill(name);
  await confirm.getByRole('button', { name: 'Delete' }).click();
  await expect(confirm).toBeHidden();
});
