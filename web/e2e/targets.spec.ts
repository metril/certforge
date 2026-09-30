import { expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { snap } from './screens';

// lib/help.ts's 'target.runsOnForced'/'target.runsOnLocked' text, copied
// rather than imported: that module reads `import.meta.env` (a Vite-only
// global), which doesn't exist under Playwright's own Node-based test runner
// (same convention as vault.spec.ts's own REWRAP_NO_PREVIOUS).
const RUNS_ON_FORCED = 'This type can only run here.';
const RUNS_ON_LOCKED = 'Fixed once the target exists. Create a new target to change it.';

test('vault-kv sheet runs on server', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  await page.getByRole('button', { name: 'Add target' }).click();
  const sheet = page.getByRole('dialog', { name: 'Add deploy target' });
  await expect(sheet).toBeVisible();

  const vaultKv = sheet.getByRole('radio', { name: /^Vault KV/ });
  await vaultKv.click();
  await expect(vaultKv.getByText('Server')).toBeVisible();

  // exact: true — the type segment's own accessible name ("Vault KV Server")
  // otherwise substring-matches the bare "Server"/"Agent" runs-on radios too.
  const runsOnServer = sheet.getByRole('radio', { name: 'Server', exact: true });
  await expect(runsOnServer).toHaveAttribute('aria-checked', 'true');
  const runsOnAgent = sheet.getByRole('radio', { name: 'Agent', exact: true });
  await expect(runsOnAgent).toBeDisabled();
  // force: true — the disabled ToggleGroup item's own real hover target is
  // its wrapping tooltip-trigger span (SegmentedControl), same convention
  // as vault.spec.ts's own disabled Rewrap-now hover.
  await runsOnAgent.hover({ force: true });
  await expect(page.getByRole('tooltip')).toContainText(RUNS_ON_FORCED);

  // Admin has keys:export, so Include private key is not gated.
  await expect(sheet.getByRole('switch', { name: 'Include private key' })).toBeEnabled();

  await snap(page, 'target-sheet-vault-kv');

  // Cancel — nothing saved, so this test has no Vault dependency.
  await sheet.getByRole('button', { name: 'Cancel' }).click();
  await expect(sheet).toBeHidden();
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

  const traefik = sheet.getByRole('radio', { name: /^Traefik/ });
  await traefik.click();
  await expect(traefik.getByText('Agent')).toBeVisible();
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

// issuers.spec.ts's own "server grant" and "375 px" tests leave
// e2e-vault-kv/e2e-vault-kv-375 behind (never deleted); file order
// (alphabetical, workers: 1) runs it before this file, so the list here is
// never empty regardless of what the two tests above create and clean up.
test('targets at 375 px', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.setViewportSize({ width: 375, height: 800 });
  await page.goto(`/o/${E2E.orgSlug}/delivery/targets`);
  await expect(page.getByRole('list', { name: 'Deploy targets' })).toBeVisible();
  expect(await page.evaluate(() => document.scrollingElement!.scrollWidth)).toBeLessThanOrEqual(375);

  await page.getByRole('button', { name: 'Add target' }).click();
  const sheet = page.getByRole('dialog', { name: 'Add deploy target' });
  await expect(sheet).toBeVisible();

  // Below sm, the type segment's RunsOnChip is compact: icon + aria-label,
  // no visible word (so two segments fit at 375px — UI conventions).
  const traefik = sheet.getByRole('radio', { name: /^Traefik/ });
  await expect(traefik.getByText('Agent', { exact: true })).toHaveCount(0);
  await expect(traefik.locator('[aria-label="Agent"]')).toHaveCount(1);

  expect(await page.evaluate(() => document.scrollingElement!.scrollWidth)).toBeLessThanOrEqual(375);
  await snap(page, 'targets-mobile');
  await sheet.getByRole('button', { name: 'Cancel' }).click();
});
