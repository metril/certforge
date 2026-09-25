import { expect, request, type APIRequestContext, type Page } from '@playwright/test';
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
