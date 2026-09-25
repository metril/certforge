import { http, HttpResponse } from 'msw';
import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';
import { oidcErrorMessage } from './oidcError';

const oidcOn = () => http.get(url('/auth/methods'), () => HttpResponse.json({ oidcEnabled: true, localEnabled: true }));

it('puts single sign-on first and the password behind break-glass', async () => {
  server.use(...authHandlers({ authed: false }), oidcOn());
  const { user } = renderRoute('/login?next=%2Fo%2Facme%2Foverview');
  const sso = await screen.findByRole('link', { name: 'Sign in with single sign-on' });
  expect(sso).toHaveAttribute('href', '/api/v1/auth/oidc/start?next=%2Fo%2Facme%2Foverview');
  expect(screen.queryByLabelText('Admin password')).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Break-glass login' }));
  expect(await screen.findByLabelText('Admin password')).toBeVisible();
});

it('shows the password form directly when single sign-on is off', async () => {
  server.use(...authHandlers({ authed: false }));
  renderRoute('/login');
  expect(await screen.findByLabelText('Admin password')).toBeVisible();
  expect(screen.queryByRole('link', { name: /single sign-on/ })).not.toBeInTheDocument();
});

it.each([
  ['user_disabled', 'Your account is disabled. Ask an administrator.'],
  ['oidc_state', 'The sign-in expired or was interrupted. Try again.'],
  ['oidc_denied', 'The identity provider refused the sign-in.'],
  ['oidc_disabled', 'Single sign-on is not configured.'],
  ['something_new', 'Single sign-on failed. Try again.'],
  ['x'.repeat(500), 'Single sign-on failed. Try again.'],
])('maps ?error=%s to one line', async (code, text) => {
  server.use(...authHandlers({ authed: false }), oidcOn());
  renderRoute(`/login?error=${encodeURIComponent(code)}`);
  expect(await screen.findByRole('alert')).toHaveTextContent(text);
  expect(screen.getByRole('button', { name: 'Break-glass login' })).toBeEnabled();
});

it('shows the retry time on a rate-limited password login', async () => {
  // Two calls, not one: msw checks handlers within a single server.use()
  // batch in listed order (first match wins), so the 429 mock must be
  // registered after authHandlers' own /auth/login default to take
  // priority over it.
  server.use(...authHandlers({ authed: false }));
  server.use(
    http.post(url('/auth/login'), () => problem(429, 'Wait before trying again.', { 'Retry-After': '30' }, 'Too many login attempts')),
  );
  const { user } = renderRoute('/login');
  await user.type(await screen.findByLabelText('Admin password'), 'whatever-password');
  await user.click(screen.getByRole('button', { name: 'Sign in' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Wait before trying again. Retry in 30s.');
});

it('keeps the known codes in one table', () => {
  expect(oidcErrorMessage('oidc_failed')).toBe('Single sign-on failed. Try again.');
});

it('sanitises an unsafe ?next= before it reaches the single sign-on link', async () => {
  server.use(...authHandlers({ authed: false }), oidcOn());
  renderRoute('/login?next=%2F%2Fevil');
  const sso = await screen.findByRole('link', { name: 'Sign in with single sign-on' });
  expect(sso).toHaveAttribute('href', '/api/v1/auth/oidc/start?next=%2F');
});
