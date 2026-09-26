import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import type { Client } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, iso, makeClient, makeSite, meWith, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let client: Client;
let patched: unknown;
let calls: string[];

beforeEach(() => {
  client = makeClient({ siteId: 's-1', agentCertNotAfter: iso(5) });
  patched = undefined;
  calls = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/sites'), () => HttpResponse.json({ items: [makeSite({ id: 's-1', name: 'Rack A' }), makeSite({ id: 's-2', name: 'Rack B' })] })),
    http.get(url('/orgs/org-1/clients/cl-1'), () => HttpResponse.json(client)),
    http.patch(url('/orgs/org-1/clients/cl-1'), async ({ request }) => {
      patched = await request.json();
      client = { ...client, ...(patched as Partial<Client>) };
      return HttpResponse.json(client);
    }),
    http.post(url('/orgs/org-1/clients/cl-1/revoke'), () => {
      calls.push('revoke');
      client = { ...client, status: 'revoked', connected: false, online: false };
      return HttpResponse.json(client);
    }),
    http.post(url('/orgs/org-1/clients/cl-1/reenroll'), () => {
      calls.push('reenroll');
      client = { ...client, status: 'pending', connected: false, online: false };
      return HttpResponse.json({ client, token: 'cf1.aHR0cHM6Ly9jZg.ab12.s3cret', expiresAt: iso(1), agentUrl: 'https://cf.lan:8443' });
    }),
    http.delete(url('/orgs/org-1/clients/cl-1'), () => {
      calls.push('delete');
      return new HttpResponse(null, { status: 204 });
    }),
  );
});

it('shows the header facts', async () => {
  renderRoute('/o/acme/clients/cl-1/settings');
  expect(await screen.findByRole('heading', { name: 'web-1' })).toBeInTheDocument();
  const header = screen.getByRole('region', { name: 'Client summary' });
  expect(within(header).getByText('Connected')).toBeInTheDocument();
  expect(within(header).getByText('web-1.lan')).toBeInTheDocument();
  expect(within(header).getByText('Rack A')).toBeInTheDocument();
  expect(within(header).getByText('0.3.0 · linux/amd64')).toBeInTheDocument();
  expect(within(header).getByText('Expires in 5 d')).toBeInTheDocument();
  expect(within(within(header).getByRole('list', { name: 'Capabilities' })).getAllByRole('listitem').map((l) => l.textContent)).toEqual(['traefik', 'hooks']);
});

it('labels a pull-only client Online (pull)', async () => {
  client = makeClient({ connected: false, online: true });
  renderRoute('/o/acme/clients/cl-1/settings');
  expect(await screen.findByText('Online (pull)')).toBeInTheDocument();
});

it('labels an offline client with the time it went away', async () => {
  client = makeClient({ connected: false, online: false, lastSeen: '2026-09-24T09:05:00Z' });
  renderRoute('/o/acme/clients/cl-1/settings');
  expect(await screen.findByText(/^Offline since /)).toBeInTheDocument();
});

it('renames and moves the client, showing a duplicate name inline', async () => {
  const { user } = renderRoute('/o/acme/clients/cl-1/settings');
  const name = await screen.findByLabelText('Name');
  await user.clear(name);
  await user.type(name, 'web-2');
  await user.click(screen.getByRole('combobox', { name: 'Site' }));
  await user.click(await screen.findByRole('option', { name: 'Rack B' }));
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toEqual({ name: 'web-2', siteId: 's-2' }));
  server.use(http.patch(url('/orgs/org-1/clients/cl-1'), () => problem(409, 'A client named db-1 already exists.')));
  await user.clear(screen.getByLabelText('Name'));
  await user.type(screen.getByLabelText('Name'), 'db-1');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  expect(await screen.findByText('A client named db-1 already exists.')).toBeInTheDocument();
});

it('re-enrol dialog shows the token once and forgets it on Done', async () => {
  const { user, queryClient } = renderRoute('/o/acme/clients/cl-1/settings');
  await user.click(await screen.findByRole('button', { name: 'Re-enrol' }));
  await user.type(screen.getByLabelText(/to confirm/), 'web-1');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Re-enrol' }));
  const dialog = await screen.findByRole('dialog', { name: 'New token for web-1' });
  expect(within(dialog).getByText('cf1.aHR0cHM6Ly9jZg.ab12.s3cret')).toBeInTheDocument();
  await user.click(within(dialog).getByRole('button', { name: 'Done' }));
  await waitFor(() => expect(screen.queryByText('cf1.aHR0cHM6Ly9jZg.ab12.s3cret')).not.toBeInTheDocument());
  expect(calls).toEqual(['reenroll']);
  expect(JSON.stringify(queryClient.getMutationCache().getAll().map((m) => m.state.data ?? null))).not.toContain('s3cret');
});

it('revokes with the name typed, then allows delete and returns to the list', async () => {
  const { user, router } = renderRoute('/o/acme/clients/cl-1/settings');
  expect(await screen.findByRole('button', { name: 'Delete' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Revoke' }));
  await user.type(screen.getByLabelText(/to confirm/), 'web-1');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Revoke' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  await waitFor(() => expect(screen.getByRole('button', { name: 'Delete' })).toBeEnabled());
  expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
  // 3A refuses re-enrolling a revoked client (409); the action is gone.
  expect(screen.queryByRole('button', { name: 'Re-enrol' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Delete' }));
  await user.type(screen.getByLabelText(/to confirm/), 'web-1');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/clients'));
  expect(calls).toEqual(['revoke', 'delete']);
});

it('is read-only for a viewer', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  renderRoute('/o/acme/clients/cl-1/settings');
  expect(await screen.findByLabelText('Name')).toBeDisabled();
  for (const name of ['Save', 'Re-enrol', 'Revoke', 'Delete']) expect(screen.getByRole('button', { name })).toBeDisabled();
});

it('All orgs redirects to the All orgs overview', async () => {
  const { router } = renderRoute('/o/all/clients/cl-1/settings');
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/all/overview'));
});

it('redirects an unknown tab to the default one', async () => {
  const { router } = renderRoute('/o/acme/clients/cl-1/nope');
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/clients/cl-1/settings'));
});
