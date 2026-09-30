import { readFile } from 'node:fs/promises';
import type { Locator } from '@playwright/test';
import { expect, signInLocal, test } from './auth';
import { E2E } from './env';
import { snap } from './screens';

// RJSF's own default text widget (theme/templates.tsx's BaseInputTemplate,
// used for every plain — non-secret — string/integer field, e.g. the SMTP
// section's Host/Port/From address) never picks up a value `.fill()` sets:
// the native `input` event does fire (confirmed directly), but React's own
// synthetic layer never observes it as a real change, so the field's own
// `onChange` — and therefore the section's dirty state and Save button —
// never fires either. Every other field in this suite is either a plain
// component outside SchemaForm (ChannelSheet/MonitorSheet's own Name/Host)
// or a custom widget (SecretInput), neither of which hits this; real
// key-by-key typing (`pressSequentially`) does not have the problem.
async function typeInto(locator: Locator, text: string): Promise<void> {
  await locator.click();
  await locator.press('ControlOrMeta+A');
  await locator.pressSequentially(text);
}

// lib/help.ts's own 'backup.needsEscrow' text, copied rather than imported:
// that module reads `import.meta.env` (a Vite-only global), which doesn't
// exist under Playwright's own Node-based test runner (same precedent as
// vault.spec.ts's REWRAP_NO_PREVIOUS).
const BACKUP_NEEDS_ESCROW = 'Confirm the KEK is stored safely first. Without it no backup can be restored.';

type MailpitList = { messages: { ID: string }[] };

/** Polls mailpit's own HTTP API (bounded 60 s), the same convention as
 * test/e2e/ops_test.go's waitForMailpitReady/opsMailpitMessages. */
async function waitForMailpitMessage(to: string): Promise<void> {
  const deadline = Date.now() + 60_000;
  for (;;) {
    const res = await fetch(`${E2E.mailpitApi}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`);
    if (res.ok) {
      const list = (await res.json()) as MailpitList;
      if (list.messages.length > 0) return;
    }
    if (Date.now() > deadline) throw new Error(`no mailpit message to ${to} within 60s`);
    await new Promise((r) => setTimeout(r, 1_000));
  }
}

test('SMTP test via mailpit', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.goto('/settings/integrations');

  // Scoped to the Email (SMTP) block itself, not a fragile class selector —
  // IntegrationsSection stacks several SchemaSection blocks (Vault, Email,
  // Notifications, Prometheus) on one page, each with its own Save button.
  // A div containing both the section's own "Send test email" button and
  // its Host field is either the section's own outer div or one of its
  // ancestors (e.g. the whole IntegrationsSection); `.last()` picks the
  // innermost (most specific) one — its own outer div.
  const email = page
    .locator('div')
    .filter({ has: page.getByRole('button', { name: 'Send test email' }) })
    .filter({ has: page.getByLabel('Host', { exact: true }) })
    .last();
  await typeInto(email.getByLabel('Host', { exact: true }), 'mailpit');
  await typeInto(email.getByLabel('Port', { exact: true }), '1025');
  await email.getByRole('radiogroup', { name: 'Security' }).getByRole('radio', { name: 'none' }).click();
  await typeInto(email.getByLabel('From address', { exact: true }), 'certforge@e2e.test');
  await email.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Settings saved')).toBeVisible();

  await email.getByLabel('Send to', { exact: true }).fill('ops@e2e.test');
  await email.getByRole('button', { name: 'Send test email' }).click();
  await expect(email.getByText('Delivered')).toBeVisible({ timeout: 30_000 });

  await waitForMailpitMessage('ops@e2e.test');
  await snap(page, 'integrations-ops');
});

test('prometheus scrape', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.goto('/settings/integrations');

  // Scoped to the Prometheus block itself (same double-filter convention as
  // the Email block above). Pairing "Enabled" with "Bearer token" would
  // instead resolve to RJSF's own form-root wrapper div, since both fields
  // live inside the same SchemaForm — one criterion must come from outside
  // the form (the section's own Save button, a sibling of the form) to
  // force the match up to the section's own outer div.
  const prom = page
    .locator('div')
    .filter({ has: page.getByRole('switch', { name: 'Enabled' }) })
    .filter({ has: page.getByRole('button', { name: 'Save' }) })
    .last();
  await prom.getByRole('switch', { name: 'Enabled' }).click();
  await prom.getByLabel('Bearer token', { exact: true }).fill('e2e-metrics-token-0123456789');
  await prom.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Settings saved')).toBeVisible();
  await expect(prom.getByText(/\/metrics$/)).toBeVisible();

  const unauthed = await page.request.get('/metrics');
  expect(unauthed.status()).toBe(401);
  expect(await unauthed.text()).toBe('');

  const authed = await page.request.get('/metrics', { headers: { Authorization: 'Bearer e2e-metrics-token-0123456789' } });
  expect(authed.status()).toBe(200);
  expect(await authed.text()).toContain('certforge_build_info');
});

test('backup download', async ({ page }) => {
  await page.goto('/login');
  await signInLocal(page);
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));
  await page.goto('/settings/backup');

  const backUpNow = page.getByRole('button', { name: 'Back up now' });
  await expect(backUpNow).toBeDisabled();
  // force: true — the disabled button is `pointer-events: none` (Tailwind's
  // disabled: variant); the real hover target is its own wrapping tooltip
  // trigger span (same as vault.spec.ts's "keys card" Rewrap now button).
  await backUpNow.hover({ force: true });
  await expect(page.getByRole('tooltip')).toContainText(BACKUP_NEEDS_ESCROW);

  await page.getByRole('switch', { name: 'KEK escrow confirmed' }).click();
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Settings saved')).toBeVisible();
  await expect(backUpNow).toBeEnabled();

  const pending = page.waitForEvent('download');
  await backUpNow.click();
  const download = await pending;
  expect(download.suggestedFilename()).toMatch(/^certforge-\d{8}T\d{6}Z\.cfbak$/);
  const buf = await readFile((await download.path())!);
  expect(buf.subarray(0, 7).toString('latin1')).toBe('CFBAK1\n');
  await snap(page, 'backup');
});
