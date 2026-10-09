import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { account, authHandlers, ca, caLocal, meWith, problem, url } from '@/test/fixtures';
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

// Fix round 1 (#2, Important): a long registration URI overflowed its cell
// and covered the row's Delete button; `table-fixed` plus `min-w-0`/`truncate`
// on the cell and its code element keep it inside the column.
it('truncates a long registration URI within its cell', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([account])),
  );
  renderRoute('/o/acme/issuers/accounts');
  const row = (await screen.findByText('ops@example.com')).closest('tr')!;
  const cell = within(row).getByText(account.registrationUri).closest('td')!;
  expect(cell.className).toMatch(/min-w-0/);
  expect(cell.className).toMatch(/overflow-hidden/);
  expect(within(row).getByText(account.registrationUri).parentElement!.className).toMatch(/max-w-full/);
  const code = within(row).getByText(account.registrationUri);
  expect(code.tagName).toBe('CODE');
  expect(code.className).toMatch(/truncate/);
  expect(code.className).toMatch(/min-w-0/);
});

// Fix round 2 (Important): a plain network failure (fetch rejects) is not an
// ApiError; it must still surface as a form-level error, not just stop the
// button spinning silently.
it('shows a form-level error when registering fails with a non-API error', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.post(url('/orgs/org-1/acme-accounts'), () => HttpResponse.error()),
  );
  const { user } = renderRoute('/o/acme/issuers/accounts');
  await user.click(await screen.findByRole('button', { name: 'Register account' }));
  const dialog = screen.getByRole('dialog', { name: 'Register ACME account' });
  await user.click(within(dialog).getByRole('combobox', { name: 'Certificate authority' }));
  await user.click(screen.getByRole('option', { name: "Let's Encrypt" }));
  await user.type(within(dialog).getByLabelText('Contact email'), 'new@example.com');
  await user.click(within(dialog).getByRole('button', { name: 'Register' }));
  expect(await within(dialog).findByRole('alert')).toBeInTheDocument();
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

// Fix round 2 (Important #1): a viewer has accounts:read but not
// accounts:write — Register account and Delete stay visible but disabled.
it('disables Register account and Delete for a viewer', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: 'org-1' }]))),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([account])),
  );
  renderRoute('/o/acme/issuers/accounts');
  expect(await screen.findByRole('button', { name: 'Register account' })).toBeDisabled();
  expect(screen.getByRole('button', { name: `Delete ${account.email}` })).toHaveAttribute('aria-disabled', 'true');
});

it('offers only ACME CAs when registering an account', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca, caLocal])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
  );
  const { user } = renderRoute('/o/acme/issuers/accounts');
  await user.click(await screen.findByRole('button', { name: 'Register account' }));
  const dialog = screen.getByRole('dialog', { name: 'Register ACME account' });
  await user.click(within(dialog).getByRole('combobox', { name: 'Certificate authority' }));
  expect(screen.getByRole('option', { name: "Let's Encrypt" })).toBeInTheDocument();
  expect(screen.queryByRole('option', { name: caLocal.name })).toBeNull();
});
