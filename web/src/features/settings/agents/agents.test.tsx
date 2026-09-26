import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeAll, beforeEach, expect, it } from 'vitest';
import type { AgentCA } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, iso, makeAgentCA, meWith, org, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

beforeAll(async () => {
  await import('../SettingsPage');
});

let cas: AgentCA[];
let listenerNotAfter: string | null;
let put: unknown;
let calls: string[];

beforeEach(() => {
  cas = [
    makeAgentCA({ id: 'aca-2', fingerprint: 'ef'.repeat(32), activeClientCerts: 1 }),
    makeAgentCA({ id: 'aca-1', status: 'retiring', activeClientCerts: 0 }),
    makeAgentCA({ id: 'aca-0', status: 'retired', fingerprint: '01'.repeat(32), activeClientCerts: 0 }),
  ];
  listenerNotAfter = iso(240);
  put = undefined;
  calls = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/settings/agents'), () =>
      HttpResponse.json({
        section: 'agents',
        schema: {
          type: 'object',
          properties: {
            agentUrl: { type: 'string', title: 'Agent URL', description: 'The address agents dial.' },
            heartbeatSeconds: { type: 'integer', title: 'Heartbeat interval (seconds)', minimum: 15, default: 60 },
          },
        },
        value: { agentUrl: '', heartbeatSeconds: 60 },
        stored: null,
        storedSecrets: [],
      }),
    ),
    http.put(url('/settings/agents'), async ({ request }) => {
      put = await request.json();
      return HttpResponse.json({});
    }),
    http.get(url('/agents/ca'), () =>
      HttpResponse.json({ items: cas, listener: { caId: 'aca-2', names: ['cf.lan', 'localhost'], notAfter: listenerNotAfter } }),
    ),
    http.post(url('/agents/ca/rotate'), () => {
      calls.push('rotate');
      return HttpResponse.json(makeAgentCA({ id: 'aca-3' }), { status: 201 });
    }),
    http.post(url('/agents/ca/:id/retire'), ({ params }) => {
      calls.push(`retire ${params.id}`);
      return HttpResponse.json(makeAgentCA({ id: params.id as string, status: 'retired' }));
    }),
  );
});

it('is a Settings section with the schema form', async () => {
  const { user } = renderRoute('/settings/agents');
  expect(await screen.findByRole('heading', { name: 'Agents' })).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Agents' })).toHaveAttribute('aria-current', 'page');
  await user.type(await screen.findByLabelText('Agent URL'), 'https://cf.lan:8443');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(put).toMatchObject({ agentUrl: 'https://cf.lan:8443', heartbeatSeconds: 60 }));
});

it('shows the listener certificate, and flags it under 14 days', async () => {
  renderRoute('/settings/agents');
  const listener = await screen.findByRole('region', { name: 'Listener certificate' });
  expect(within(listener).getByText('cf.lan')).toBeInTheDocument();
  expect(within(listener).getByText('Expires in 240 d')).toBeInTheDocument();
  expect(within(listener).getByText('efefefefefef…')).toBeInTheDocument();
});

it('rotates by typing rotate, and retires only an unused retiring CA', async () => {
  const { user } = renderRoute('/settings/agents');
  const list = await screen.findByRole('list', { name: 'Agent CAs' });
  const [active, retiring, retired] = within(list).getAllByRole('listitem');
  expect(within(active!).getByText('Active')).toBeInTheDocument();
  expect(within(active!).getByText('1 agent')).toBeInTheDocument();
  expect(within(active!).queryByRole('button', { name: 'Retire' })).not.toBeInTheDocument();
  expect(within(retired!).getByText('Retired')).toBeInTheDocument();
  await user.click(within(retiring!).getByRole('button', { name: 'Retire' }));
  await user.type(screen.getByLabelText(/to confirm/), 'retire');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Retire' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  await user.click(screen.getByRole('button', { name: 'Rotate' }));
  await user.type(screen.getByLabelText(/to confirm/), 'rotate');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Rotate' }));
  await waitFor(() => expect(calls).toEqual(['retire aca-1', 'rotate']));
});

it('keeps Retire disabled while agents still use the CA', async () => {
  cas = [makeAgentCA({ id: 'aca-1', status: 'retiring', activeClientCerts: 2 })];
  renderRoute('/settings/agents');
  expect(await screen.findByRole('button', { name: 'Retire' })).toBeDisabled();
});

it('is read-only without settings:write', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))));
  renderRoute('/settings/agents');
  expect(await screen.findByRole('button', { name: 'Rotate' })).toBeDisabled();
  expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
});

it('says when the listener is not running', async () => {
  listenerNotAfter = null;
  renderRoute('/settings/agents');
  expect(await screen.findByText('The agent listener is not running.')).toBeInTheDocument();
});
