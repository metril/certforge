import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import type { ClientCreated } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, iso, makeClient, makeSite, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

const TOKEN = 'cf1.aHR0cHM6Ly9jZi5sYW46ODQ0Mw.ab12.s3cret';
const pending = makeClient({ id: 'cl-9', name: 'edge-1', status: 'pending', connected: false, online: false, lastSeen: null, hostname: '', agentVersion: '' });
let created: ClientCreated;
let body: unknown;
let polls: number;

beforeEach(() => {
  created = { client: pending, token: TOKEN, expiresAt: iso(1), agentUrl: 'https://cf.lan:8443' };
  polls = 0;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/sites'), () => HttpResponse.json({ items: [makeSite({ id: 's-1', name: 'Rack A' })] })),
    http.post(url('/orgs/org-1/clients'), async ({ request }) => {
      body = await request.json();
      return HttpResponse.json(created, { status: 201 });
    }),
    http.get(url('/orgs/org-1/clients/cl-9'), () => {
      polls++;
      return HttpResponse.json(polls < 2 ? pending : makeClient({ id: 'cl-9', name: 'edge-1', hostname: 'edge-1.lan' }));
    }),
  );
});

async function createToken() {
  const r = renderRoute('/o/acme/clients/new');
  await r.user.type(await screen.findByLabelText('Name'), 'edge-1');
  await r.user.click(screen.getByRole('combobox', { name: 'Site' }));
  await r.user.click(await screen.findByRole('option', { name: 'Rack A' }));
  await r.user.click(screen.getByRole('button', { name: 'Create token' }));
  return r;
}

// 10 s: the 2 s poll plus route load comes before the 5 s wait for Online.
it('creates a pending client, shows token and snippets, then sees the agent online', async () => {
  const { user } = await createToken();
  const token = await screen.findByRole('region', { name: 'Enrolment token' });
  expect(body).toEqual({ name: 'edge-1', siteId: 's-1' });
  expect(within(token).getByText(TOKEN)).toBeInTheDocument();
  expect(within(token).getByLabelText('docker run command')).toHaveTextContent(`CF_AGENT_TOKEN='${TOKEN}'`);
  await user.click(within(token).getByRole('radio', { name: 'Compose' }));
  expect(within(token).getByLabelText('Compose file')).toHaveTextContent('image: ghcr.io/metril/certforge-agent:latest');
  expect(screen.getByText('Waiting for agent')).toBeInTheDocument();
  await waitFor(() => expect(within(screen.getByRole('region', { name: 'Agent connection' })).getByText('Online')).toBeInTheDocument(), { timeout: 5000 });
  expect(screen.getByText('edge-1.lan · linux/amd64 · 0.3.0')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Grant certificate' })).toHaveAttribute('href', '/o/acme/clients/cl-9/certificates?grant=new');
}, 10_000);

it('shows a duplicate name under the field', async () => {
  server.use(http.post(url('/orgs/org-1/clients'), () => problem(409, 'A client named edge-1 already exists.')));
  await createToken();
  expect(await screen.findByText('A client named edge-1 already exists.')).toBeInTheDocument();
  expect(screen.getByLabelText('Name')).toHaveAttribute('aria-invalid', 'true');
});

it('expired token: offers a new one while still pending', async () => {
  created = { ...created, expiresAt: iso(-1) };
  server.use(
    http.get(url('/orgs/org-1/clients/cl-9'), () => HttpResponse.json(pending)),
    http.post(url('/orgs/org-1/clients/cl-9/reenroll'), () =>
      HttpResponse.json({ client: pending, token: 'cf1.aHR0cHM6Ly9jZi5sYW46ODQ0Mw.ab12.fresh', expiresAt: iso(1), agentUrl: 'https://cf.lan:8443' }),
    ),
  );
  const { user } = await createToken();
  expect(await screen.findByText('Token expired')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'New token' }));
  expect(await screen.findByText('cf1.aHR0cHM6Ly9jZi5sYW46ODQ0Mw.ab12.fresh')).toBeInTheDocument();
  expect(screen.getByText('Waiting for agent')).toBeInTheDocument();
});

it('drops the token on leave', async () => {
  const { router, queryClient } = await createToken();
  await screen.findByText(TOKEN);
  await router.navigate({ to: '/o/$org/clients', params: { org: 'acme' } });
  await screen.findByRole('heading', { name: 'Clients' });
  expect(screen.queryByText(TOKEN)).not.toBeInTheDocument();
  const cached = JSON.stringify(queryClient.getMutationCache().getAll().map((m) => m.state.data ?? null));
  expect(cached).not.toContain('s3cret');
});
