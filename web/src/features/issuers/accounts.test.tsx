import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { account, authHandlers, ca, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

it('lists accounts and registers a new one', async () => {
  let body: unknown;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([account])),
    http.post(url('/orgs/org-1/acme-accounts'), async ({ request }) => {
      body = await request.json();
      return HttpResponse.json({ ...account, id: 'acc-2', email: 'new@example.com' }, { status: 201 });
    }),
  );
  const { user } = renderRoute('/o/acme/issuers/accounts');
  const row = (await screen.findByText('ops@example.com')).closest('tr')!;
  expect(within(row).getByText('Valid')).toBeInTheDocument();
  expect(within(row).getByText("Let's Encrypt")).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Register account' }));
  const dialog = screen.getByRole('dialog', { name: 'Register ACME account' });
  await user.click(within(dialog).getByRole('combobox', { name: 'Certificate authority' }));
  await user.click(screen.getByRole('option', { name: "Let's Encrypt" }));
  await user.type(within(dialog).getByLabelText('Contact email'), 'new@example.com');
  await user.click(within(dialog).getByRole('button', { name: 'Register' }));
  await waitFor(() => expect(body).toEqual({ caId: 'ca-1', email: 'new@example.com' }));
});

it('shows why an account cannot be deleted', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([account])),
    http.delete(url('/orgs/org-1/acme-accounts/:id'), () => problem(409, 'Account is used by 1 certificate')),
  );
  const { user } = renderRoute('/o/acme/issuers/accounts');
  await screen.findByText('ops@example.com');
  await user.click(screen.getByRole('button', { name: 'Delete ops@example.com' }));
  const dialog = screen.getByRole('dialog');
  await user.type(within(dialog).getByRole('textbox'), 'ops@example.com');
  await user.click(within(dialog).getByRole('button', { name: 'Delete account' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('Account is used by 1 certificate');
});
