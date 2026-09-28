import type { Page } from '@playwright/test';

/** Sets the app's own theme preference, not just the CSS-only `data-theme`
 * attribute: `lib/theme.tsx`'s `ThemeProvider` also drives the Toaster
 * (`app/Providers.tsx`), which reads its `theme` prop from React state, not
 * from the DOM — a screenshot taken right after a toast (e.g.
 * settings-agents, right after "Settings saved") needs the account menu's
 * real Light/Dark toggle for that toast to render in the right theme, not
 * just CSS variables to flip. When a modal (a sheet or dialog) covers the
 * account menu trigger, e.g. layout-sheet, there is no toast in that
 * screenshot either way, so setting the CSS-only attributes directly is enough. */
export async function setTheme(page: Page, t: 'light' | 'dark') {
  const trigger = page.getByRole('button', { name: /^Account menu for / });
  if (await trigger.isVisible()) {
    await trigger.click();
    await page.getByRole('radio', { name: t === 'light' ? 'Light' : 'Dark' }).click();
    await page.keyboard.press('Escape');
  } else {
    await page.evaluate((theme) => {
      document.documentElement.setAttribute('data-theme', theme);
      document.documentElement.style.colorScheme = theme;
    }, t);
  }
}

/** Screenshots the page in both themes without a reload (state that lives
 * only in the page, e.g. an enrolment token or an unsaved sheet, survives
 * the theme toggle), then goes back to light. */
export async function snap(page: Page, name: string) {
  for (const theme of ['light', 'dark'] as const) {
    await setTheme(page, theme);
    // A sheet's slide-in is a CSS animation, not a transition Playwright's
    // own actionability waits settle on: without freezing it, a screenshot
    // taken right after a fill/click can catch the panel mid-slide, still
    // partly off the right edge of the viewport (observed on layout-sheet).
    await page.screenshot({ path: `test-results/screens/${theme}-${name}.png`, fullPage: true, animations: 'disabled' });
  }
  await setTheme(page, 'light');
}
