import { expect, type Locator } from '@playwright/test';

/** Picks a deploy-target type in the sheet. The Type field is a radio
 * SegmentedControl with <= 5 types and a searchable Combobox above that, so
 * handle both. */
export async function pickTargetType(sheet: Locator, name: RegExp | string): Promise<void> {
  const radio = sheet.getByRole('radio', { name });
  if (await radio.first().isVisible()) {
    await radio.first().click();
    return;
  }
  await sheet.getByRole('combobox', { name: 'Type' }).click();
  // The popover is portaled outside the sheet, so search from the page.
  const page = sheet.page();
  await page.getByPlaceholder('Search').fill(typeof name === 'string' ? name : name.source.replace(/^\^/, ''));
  // Option name is "<label> <hint>" (e.g. "Vault KV Server").
  await page.getByRole('option', { name }).first().click();
  // Let the popover finish closing so it cannot swallow later pointer events.
  await expect(page.getByPlaceholder('Search')).toBeHidden();
}

/** Asserts the Runs on control reflects the picked type's mode; works for
 * both Type renderings (the Runs on radios always exist). */
export async function expectRunsOn(sheet: Locator, mode: 'Server' | 'Agent'): Promise<void> {
  await expect(sheet.getByRole('radio', { name: mode, exact: true })).toHaveAttribute('aria-checked', 'true');
}

/** Cancels the sheet; a changed form asks to discard first, so confirm that. */
export async function cancelSheet(sheet: Locator): Promise<void> {
  await sheet.getByRole('button', { name: 'Cancel' }).click();
  const discard = sheet.page().getByRole('dialog', { name: 'Discard changes?' });
  if (await discard.isVisible()) await discard.getByRole('button', { name: 'Discard' }).click();
  await expect(sheet).toBeHidden();
}
