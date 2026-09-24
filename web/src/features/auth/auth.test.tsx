import { http } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import { expect, it } from 'vitest';
import { api, call } from '@/api/client';
import { server } from '@/test/server';
import { authHandlers, PASSWORD, unauthorized, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

it('sends a signed-out deep link through login and back', async () => {
  server.use(...authHandlers({ authed: false }));
  const { router, user } = renderRoute('/o/acme/overview?focus=failed');
  await screen.findByLabelText('Admin password');
  expect(router.state.location.search).toEqual({ next: '/o/acme/overview?focus=failed' });
  await user.type(screen.getByLabelText('Admin password'), PASSWORD);
  await user.click(screen.getByRole('button', { name: 'Sign in' }));
  await waitFor(() => expect(router.state.location.href).toBe('/o/acme/overview?focus=failed'));
});

it('shows a wrong password inline and stays on login', async () => {
  server.use(...authHandlers({ authed: false }));
  const { router, user } = renderRoute('/login');
  await user.type(await screen.findByLabelText('Admin password'), 'nope');
  await user.click(screen.getByRole('button', { name: 'Sign in' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Wrong password.');
  expect(router.state.location.pathname).toBe('/login');
});

it('sends a 401 mid-session to login once, keeping the return URL', async () => {
  const state = { authed: true };
  server.use(...authHandlers(state), http.get(url('/orgs'), () => unauthorized()));
  const { router, queryClient, user } = renderRoute('/o/acme/overview?focus=expired');
  await screen.findByRole('heading', { name: 'Overview' });
  state.authed = false;
  await Promise.all(
    [1, 2, 3].map((n) =>
      queryClient.fetchQuery({ queryKey: ['probe', n], queryFn: () => call(api.GET('/orgs')) }).catch(() => {}),
    ),
  );
  await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
  expect(router.state.location.search).toEqual({ next: '/o/acme/overview?focus=expired' });
  await user.type(screen.getByLabelText('Admin password'), PASSWORD);
  await user.click(screen.getByRole('button', { name: 'Sign in' }));
  await waitFor(() => expect(router.state.location.href).toBe('/o/acme/overview?focus=expired'));
});

it('redirects an already signed-in visitor away from /login, through safeRedirect', async () => {
  server.use(...authHandlers({ authed: true }));
  const { router } = renderRoute('/login?next=/o/acme/overview?focus=x');
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/overview'));
  expect(router.state.location.search).toEqual({ focus: 'x' });
});

it('sends a first-run visitor away from /login to /setup', async () => {
  server.use(...authHandlers({ authed: false, needsSetup: true }));
  const { router } = renderRoute('/login');
  await waitFor(() => expect(router.state.location.pathname).toBe('/setup'));
});
