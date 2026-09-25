import { expect, request, test as base, type APIRequestContext, type ConsoleMessage, type Page } from '@playwright/test';
import { E2E } from './env';

/** Signs in as the local admin, opening Break-glass login when single sign-on is on. */
export async function signInLocal(page: Page): Promise<void> {
  const breakGlass = page.getByRole('button', { name: 'Break-glass login' });
  const password = page.getByLabel('Admin password');
  await expect(breakGlass.or(password)).toBeVisible();
  if (await breakGlass.isVisible()) await breakGlass.click();
  await password.fill(E2E.password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
}

/** An API context signed in as the local admin, plus its CSRF header. */
export async function adminApi(): Promise<{ api: APIRequestContext; headers: Record<string, string> }> {
  const api = await request.newContext({ baseURL: E2E.baseURL });
  const res = await api.post('/api/v1/auth/login', { data: { password: E2E.password } });
  if (!res.ok()) throw new Error(`admin login: ${res.status()} ${await res.text()}`);
  const me = (await res.json()) as { csrfToken: string };
  return { api, headers: { 'X-CSRF-Token': me.csrfToken } };
}

// M5: a nonce/hash mismatch or a disallowed source only ever shows up as a
// browser console error at request time — Playwright never fails the test on
// its own, so every CSP violation logged during a test is collected here and
// asserted empty once the test body finishes, on top of whatever the test
// already checks. A console message is one way a violation surfaces; the
// browser's own `securitypolicyviolation` event fires for every blocked
// request regardless of whether anything is ever logged to the console, so
// both are collected. Chromium's actual wording is "...violates the
// following Content Security Policy directive..." (no hyphens), hence the
// loose regex instead of an exact literal.
const CSP_MESSAGE = /content[- ]security[- ]policy/i;

/** `test`/`expect` wired with an automatic, per-test CSP violation guard on
 * `page` — every spec that imports its `test` from here (instead of
 * `@playwright/test` directly) gets this for free, with no per-file
 * boilerplate. */
export const test = base.extend({
  page: async ({ page }, runTest) => {
    const violations: string[] = [];
    page.on('console', (msg: ConsoleMessage) => {
      if (msg.type() === 'error' && CSP_MESSAGE.test(msg.text())) violations.push(msg.text());
    });
    await page.addInitScript(() => {
      const w = window as unknown as { __cspViolations: string[] };
      w.__cspViolations = [];
      document.addEventListener('securitypolicyviolation', (e) => {
        w.__cspViolations.push(`${e.violatedDirective}: ${e.blockedURI}`);
      });
    });

    await runTest(page);

    expect(violations, 'CSP violations (console)').toEqual([]);
    expect(
      await page.evaluate(() => (window as unknown as { __cspViolations: string[] }).__cspViolations),
      'CSP violations (securitypolicyviolation)',
    ).toEqual([]);
  },
});

export { expect };
