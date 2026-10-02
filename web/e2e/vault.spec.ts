import { expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { snap } from './screens';

// lib/help.ts's 'keys.rewrapNoPrevious' text, copied rather than imported:
// that module reads `import.meta.env` (a Vite-only global), which doesn't
// exist under Playwright's own Node-based test runner.
const REWRAP_NO_PREVIOUS = 'Nothing to re-encrypt: no older key is set.';

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
  const card = page.getByRole('region', { name: 'Encryption key' });
  await expect(card).toBeVisible();
  // e2e-web boots with a static KEK and no previous key (5a-facts.md).
  // exact: true — otherwise this also matches the Key ID's own
  // "static-<hex>" text (case-insensitive substring).
  await expect(card.getByText('Static', { exact: true })).toBeVisible();
  const keyId = card.locator('dd').filter({ has: page.locator('code') }).first();
  await expect(keyId.locator('code')).not.toBeEmpty();
  await expect(card.getByText('Key check OK')).toBeVisible();

  const rewrap = card.getByRole('button', { name: 'Re-encrypt now' });
  await expect(rewrap).toBeDisabled();
  // force: true — the disabled button itself is `pointer-events: none`
  // (Tailwind's disabled: variant); the real hover target the browser
  // hit-tests to is its own wrapping tooltip-trigger span, so Playwright's
  // own actionability check (which insists on hovering the button element
  // exactly) never settles without it.
  await rewrap.hover({ force: true });
  await expect(page.getByRole('tooltip')).toContainText(REWRAP_NO_PREVIOUS);
  await snap(page, 'keys');
});
