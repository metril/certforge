import { http, HttpResponse } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, me, PASSWORD, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

it('walks the four setup steps, completes setup, and signs in', async () => {
  const state = { authed: false, needsSetup: true };
  let body: unknown;
  server.use(
    ...authHandlers(state),
    http.get('*/readyz', () => HttpResponse.json({ status: 'ready', checks: { database: 'ok', kek: 'ok' } })),
    http.post(url('/setup/complete'), async ({ request }) => {
      body = await request.json();
      state.needsSetup = false;
      state.authed = true;
      return HttpResponse.json(me);
    }),
  );
  const { router, user } = renderRoute('/');
  await screen.findByLabelText('Admin password');
  expect(router.state.location.pathname).toBe('/setup');

  await user.type(screen.getByLabelText('Admin password'), PASSWORD);
  await user.type(screen.getByLabelText('Confirm password'), PASSWORD);
  await user.click(screen.getByRole('button', { name: 'Next' }));

  expect(screen.getByLabelText('Base URL')).toHaveValue('http://localhost:3000');
  expect(screen.getByText('Matches this browser')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Next' }));

  expect(await screen.findByText('kek')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Next' }));

  await user.type(screen.getByLabelText('Organization'), 'Acme');
  expect(screen.getByLabelText('Slug')).toHaveValue('acme');
  await user.click(screen.getByRole('button', { name: 'Finish setup' }));

  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/overview'));
  expect(body).toEqual({ adminPassword: PASSWORD, orgName: 'Acme', orgSlug: 'acme', baseUrl: 'http://localhost:3000' });
});

it('blocks the key step while the server is not ready', async () => {
  server.use(
    ...authHandlers({ authed: false, needsSetup: true }),
    http.get('*/readyz', () => HttpResponse.json({ status: 'unavailable', checks: { database: 'ok', kek: 'failed' } }, { status: 503 })),
  );
  const { user } = renderRoute('/setup');
  await user.type(await screen.findByLabelText('Admin password'), PASSWORD);
  await user.type(screen.getByLabelText('Confirm password'), PASSWORD);
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await user.click(screen.getByRole('button', { name: 'Next' }));
  expect(await screen.findByText('failed')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
});
