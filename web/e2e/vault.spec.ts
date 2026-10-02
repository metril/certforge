import { expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { snap } from './screens';

// The quiet row's tooltip, copied rather than imported from the app: lib/help.ts
// reads `import.meta.env` (a Vite-only global), which doesn't exist under
// Playwright's own Node-based test runner.
const KEY_ROW_TOOLTIP = "Set in the server's environment. Needed to restore any backup. To replace it, set the new key as CF_KEK, move the old one to CF_KEK_PREVIOUS, and restart.";

test('Vault settings test button', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.goto('/settings/integrations');
  // Scoped to the Vault block itself: IntegrationsSection stacks several
  // SchemaSection blocks on one page (6B added Email, Notifications and
  // Prometheus alongside this 5B one) — a bare `getByLabel('Address')`
  // substring-matches the Email section's own "From address" field, and a
  // bare "Save" now matches all four sections' own Save buttons. One
  // criterion from inside the form (Address) and one from the actions row
  // outside it (Test connection) forces the match up to this section's own
  // outer div, not RJSF's own form-root wrapper (same convention as
  // ops.spec.ts's Email/Prometheus scoping).
  const vault = page
    .locator('div')
    .filter({ has: page.getByRole('button', { name: 'Test connection' }) })
    .filter({ has: page.getByLabel('Address', { exact: true }) })
    .last();
  const address = vault.getByLabel('Address', { exact: true });
  await expect(address).toBeVisible();

  // The token field may already be "Stored" (another spec's own Vault
  // settings, self-contained but the same global section) — Replace opens
  // it for editing either way; a fresh section starts editable already.
  const replaceToken = vault.getByRole('button', { name: 'Replace Token' });
  if (await replaceToken.isVisible()) await replaceToken.click();

  // getByLabel('Token') also substring-matches the "Keep stored Token"
  // button that appears once Replace is clicked; getByRole scopes to the
  // textbox only.
  const token = vault.getByRole('textbox', { name: 'Token' });
  await address.fill('http://127.0.0.1:1');
  await token.fill('not-a-real-token');
  await vault.getByRole('button', { name: 'Test connection' }).click();
  await expect(vault.getByText('Failed')).toBeVisible({ timeout: 30_000 });

  await address.fill(E2E.vaultAddr);
  const replaceAgain = vault.getByRole('button', { name: 'Replace Token' });
  if (await replaceAgain.isVisible()) await replaceAgain.click();
  await token.fill(E2E.vaultToken);
  await vault.getByRole('button', { name: 'Test connection' }).click();
  // Pre-flight ruling: Vault is always up in the compose e2e profile, so
  // this asserts Connected unconditionally.
  await expect(vault.getByText('Connected')).toBeVisible({ timeout: 30_000 });
  await snap(page, 'integrations');

  await vault.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Settings saved')).toBeVisible();

  await page.reload();
  await expect(vault.getByLabel('Address', { exact: true })).toHaveValue(E2E.vaultAddr);
  await expect(vault.getByRole('button', { name: 'Replace Token' })).toBeVisible();
});

test('keys card', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.goto('/settings/backup');
  // e2e-web boots with a static key and no older key (5a-facts.md), so the
  // card collapses to its quiet row: heading, a Key check OK chip, and a tooltip.
  await expect(page.getByRole('heading', { name: 'Encryption key' })).toBeVisible();
  await expect(page.getByText('Key check OK')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Re-encrypt now' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Help' }).last().hover();
  await expect(page.getByRole('tooltip')).toContainText(KEY_ROW_TOOLTIP);
  await snap(page, 'keys');
});
