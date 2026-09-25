import { readFile } from 'node:fs/promises';
import { expect, test, type ConsoleMessage, type Page } from '@playwright/test';
import { E2E } from './env';

const SURFACE = { light: 'rgb(246, 247, 249)', dark: 'rgb(22, 27, 36)' } as const;

// M5: a nonce/hash mismatch or a disallowed source only ever shows up as a
// browser console error at request time — Playwright never fails the test on
// its own, so every CSP violation logged during a test is collected here and
// asserted empty at the end, on top of whatever the test already checks.
const cspViolations = new WeakMap<Page, string[]>();

test.beforeEach(({ page }) => {
  const violations: string[] = [];
  cspViolations.set(page, violations);
  page.on('console', (msg: ConsoleMessage) => {
    if (msg.type() === 'error' && /Content-Security-Policy/i.test(msg.text())) violations.push(msg.text());
  });
});

test.afterEach(({ page }) => {
  expect(cspViolations.get(page)).toEqual([]);
});

for (const theme of ['light', 'dark'] as const) {
  test(`log in, see the certificate, open it, download PEM (${theme})`, async ({ page }) => {
    await page.addInitScript((t) => {
      localStorage.setItem('cf-theme', t);
      const seen: (string | null)[] = [];
      // Playwright's addInitScript runs before the document is parsed, so
      // document.documentElement is still null at this point — observe from
      // `document` with subtree instead of the (not yet existing) <html>
      // element; attributeFilter still restricts this to data-theme changes,
      // which only ever land on <html>.
      new MutationObserver((records) => {
        for (const r of records) if (r.target instanceof Element) seen.push(r.target.getAttribute('data-theme'));
      }).observe(document, { attributes: true, attributeFilter: ['data-theme'], subtree: true });
      (window as unknown as { __themes: (string | null)[] }).__themes = seen;
    }, theme);

    await page.goto('/');
    await expect(page).toHaveURL(/\/login/);
    const themes = await page.evaluate(() => (window as unknown as { __themes: (string | null)[] }).__themes);
    expect(themes.length).toBeGreaterThan(0);
    expect(new Set(themes)).toEqual(new Set([theme]));
    expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe(SURFACE[theme]);

    await page.getByLabel('Admin password').fill(E2E.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Certificates' }).click();
    const row = page.getByRole('row').filter({ has: page.getByRole('link', { name: E2E.certName, exact: true }) });
    await expect(row.getByRole('img', { name: /^Valid .* to / })).toBeVisible();
    await expect(row.getByText(/^in \d+ d$/).first()).toBeVisible();
    await page.screenshot({ path: `test-results/screens/${theme}-certificates.png`, fullPage: true });

    await row.getByRole('link', { name: E2E.certName, exact: true }).click();
    await expect(page.getByRole('heading', { level: 1, name: E2E.certName })).toBeVisible();
    await expect(page.getByRole('img', { name: /^Valid .* to / })).toBeVisible();
    // Regression check (controller review, Critical #0): a real browser's
    // WHATWG URL percent-encodes a bare "*" (%2A), which used to make the
    // catch-all "*" rule created by global-setup unmatchable — the Coverage
    // panel would show "No matching rule" for an issued certificate instead
    // of the rule that actually issued it.
    const coveragePanel = page.getByRole('region', { name: 'Coverage' });
    await expect(coveragePanel).toContainText('challtestsrv');
    await expect(coveragePanel).not.toContainText('No matching rule');
    await page.screenshot({ path: `test-results/screens/${theme}-detail.png`, fullPage: true });

    await page.getByRole('tab', { name: 'Attempts' }).click();
    await page.getByRole('button', { name: 'Raw log' }).first().click();
    await expect(page.locator('pre').filter({ hasText: /order|presenting/ }).first()).toBeVisible();
    await page.screenshot({ path: `test-results/screens/${theme}-attempts.png`, fullPage: true });

    await page.getByRole('button', { name: 'Download', exact: true }).click();
    const sheet = page.getByRole('dialog', { name: 'Download' });
    await expect(sheet.getByRole('button', { name: 'fullchain' })).toHaveAttribute('aria-pressed', 'true');

    // Regression check (C1, Critical): a Combobox's PopoverContent is
    // anchored to its trigger Button via Radix's `asChild`, which clones the
    // Button and attaches a ref to measure and position the popper. Without
    // forwardRef on Button, that ref silently dropped and the popper
    // rendered at translate(0,-200%) — off-screen — in every real browser,
    // even though jsdom-based component tests couldn't see it (jsdom doesn't
    // lay out or position anything). Only a real browser catches this.
    const versionCombobox = sheet.getByRole('combobox');
    await versionCombobox.click();
    const popper = page.locator('[data-slot="popover-content"]').last();
    await expect(popper).toBeVisible();
    const viewport = page.viewportSize()!;
    const pop = (await popper.boundingBox())!;
    expect(pop.x).toBeGreaterThanOrEqual(0);
    expect(pop.y).toBeGreaterThanOrEqual(0);
    expect(pop.x + pop.width).toBeLessThanOrEqual(viewport.width);
    expect(pop.y + pop.height).toBeLessThanOrEqual(viewport.height);
    await page.keyboard.press('Escape');

    const pending = page.waitForEvent('download');
    await sheet.getByRole('button', { name: 'Download PEM' }).click();
    const download = await pending;
    expect(download.suggestedFilename()).toMatch(/\.pem$/);
    const pem = await readFile((await download.path())!, 'utf8');
    expect(pem).toContain('-----BEGIN CERTIFICATE-----');
  });
}

test('names step wraps chips at 375px and supports a pointer drag to change the CN', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('Admin password').fill(E2E.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(new RegExp(`/o/${E2E.orgSlug}/overview`));

  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(`/o/${E2E.orgSlug}/certificates/new`);

  const names = ['first.example.test', 'second.example.test', 'third.example.test', 'fourth.example.test', 'fifth.example.test'];
  await page.getByLabel('Names').fill(names.join(', '));
  await page.getByLabel('Names').blur();

  // The chip grid (grouped by zone); scoped to avoid matching the same name
  // text in the CN slot or the wizard's summary rail.
  const chips = page.locator('section').filter({ hasText: 'example.test' });
  for (const n of names) {
    await expect(chips.getByText(n, { exact: true })).toBeVisible();
  }
  // Chips wrap onto new lines at 375px instead of forcing horizontal scroll.
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);

  // The first name added becomes the common name automatically.
  await expect(page.getByTestId('cn')).toHaveText(names[0]!);

  // Drag the second name's chip onto the "Common name" drop target to make
  // it the CN instead — a real pointer sequence, since dnd-kit's
  // PointerSensor listens for pointer events, not a synthetic HTML5 drag.
  const cnSlot = page.getByTestId('cn').locator('xpath=..');
  const chip = chips.getByText(names[1]!, { exact: true });
  const chipBox = (await chip.boundingBox())!;
  const target = cnSlot.getByText('Common name', { exact: true });
  const targetBox = (await target.boundingBox())!;

  await page.mouse.move(chipBox.x + chipBox.width / 2, chipBox.y + chipBox.height / 2);
  await page.mouse.down();
  await page.mouse.move(chipBox.x + chipBox.width / 2 + 10, chipBox.y + chipBox.height / 2 + 10, { steps: 5 });
  await page.mouse.move(targetBox.x + targetBox.width / 2, targetBox.y + targetBox.height / 2, { steps: 10 });
  await page.mouse.up();

  await expect(page.getByTestId('cn')).toHaveText(names[1]!);
});
