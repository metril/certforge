import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Channel, ChannelInput } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, iso, makeChannel, meWith, org, org2, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let channels: Channel[];
let patched: { orgId: string; id: string; body: ChannelInput } | undefined;

// The desktop DataTable path (ClientsPage's own tests use the identical
// stub); without it jsdom's default matchMedia stub (matches: false) would
// render the below-`md` card list instead in every test here.
function stubViewport(isMdUp: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)' ? isMdUp : false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}

beforeEach(() => {
  stubViewport(true);
  channels = [];
  patched = undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/channels'), () => HttpResponse.json(channels)),
    http.patch(url('/orgs/:orgId/channels/:id'), async ({ request, params }) => {
      const body = (await request.json()) as ChannelInput;
      patched = { orgId: params.orgId as string, id: params.id as string, body };
      const existing = channels.find((c) => c.id === params.id)!;
      const updated = { ...existing, ...body };
      channels = channels.map((c) => (c.id === existing.id ? updated : c));
      return HttpResponse.json(updated);
    }),
  );
});

it('three tabs link to their routes', async () => {
  renderRoute('/o/acme/alerts/channels');
  const nav = await screen.findByRole('navigation', { name: 'Alerts' });
  expect(within(nav).getByRole('link', { name: 'Channels' })).toHaveAttribute('href', '/o/acme/alerts/channels');
  expect(within(nav).getByRole('link', { name: 'Monitors' })).toHaveAttribute('href', '/o/acme/alerts/monitors');
  expect(within(nav).getByRole('link', { name: 'Events' })).toHaveAttribute('href', '/o/acme/alerts/events');
});

it('alerts index redirects to channels', async () => {
  const { router } = renderRoute('/o/acme/alerts');
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/alerts/channels'));
});

it('lists channels with type, summary and event chips', async () => {
  channels = [makeChannel({ events: ['cert.issued', 'cert.expiring'], minSeverity: 'warning' })];
  renderRoute('/o/acme/alerts/channels');
  const table = await screen.findByRole('table', { name: 'Channels' });
  expect(within(table).getByText('ops-webhook')).toBeInTheDocument();
  expect(within(table).getByText('Webhook')).toBeInTheDocument();
  expect(within(table).getByText('hooks.example.com')).toBeInTheDocument();
  expect(within(table).getByText('Certificate issued')).toBeInTheDocument();
  expect(within(table).getByText('Certificate expiring')).toBeInTheDocument();
  expect(within(table).getByText('Warning+')).toBeInTheDocument();
});

it('more than three events shows +N', async () => {
  channels = [makeChannel({ events: ['cert.issued', 'cert.expiring', 'cert.expired', 'deploy.failed'] })];
  const { user } = renderRoute('/o/acme/alerts/channels');
  const table = await screen.findByRole('table', { name: 'Channels' });
  const more = within(table).getByText('+1');
  await user.hover(more);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Deploy failed');
});

it('empty events shows All events', async () => {
  channels = [makeChannel({ events: [] })];
  renderRoute('/o/acme/alerts/channels');
  const table = await screen.findByRole('table', { name: 'Channels' });
  expect(within(table).getByText('All events')).toBeInTheDocument();
});

it('all-orgs badge and owner org', async () => {
  channels = [makeChannel({ id: 'ch-2', orgId: org2.id, allOrgs: true, name: 'global-hook' })];
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'admin', orgId: null }], [org, org2]))));
  renderRoute('/o/acme/alerts/channels');
  const table = await screen.findByRole('table', { name: 'Channels' });
  expect(within(table).getByText('All orgs')).toBeInTheDocument();
  expect(within(table).getByText('Lab')).toBeInTheDocument();
});

// The switch always sends a full ChannelInput (public config plus a stored-
// secret sentinel), targeting the channel's own org, never the route org —
// this channel is org-2's own allOrgs channel, visible on org-1's page to a
// global admin (global constraints "Wrong-org and all-orgs writes").
it('enabled switch patches full input', async () => {
  const channel = makeChannel({ id: 'c-2', orgId: org2.id, allOrgs: true, name: 'ops', storedSecrets: ['url'], config: { foo: 'bar' }, enabled: true });
  channels = [channel];
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'admin', orgId: null }], [org, org2]))));
  const { user } = renderRoute('/o/acme/alerts/channels');
  const sw = await screen.findByRole('switch', { name: 'Enabled ops' });
  await user.click(sw);
  await waitFor(() => expect(patched).toBeDefined());
  expect(patched).toEqual({
    orgId: 'org-2',
    id: 'c-2',
    body: { name: 'ops', type: 'webhook', config: { foo: 'bar', url: '__unchanged__' }, events: [], minSeverity: 'info', allOrgs: true, enabled: false },
  });
});

it('last delivery chip tooltip shows error', async () => {
  channels = [makeChannel({ lastDelivery: { status: 'failed', at: iso(0), error: 'connection refused' } })];
  const { user } = renderRoute('/o/acme/alerts/channels');
  const table = await screen.findByRole('table', { name: 'Channels' });
  const chip = within(table).getByText('Failed');
  await user.hover(chip);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('connection refused');
});

it('viewer sees disabled add and switch', async () => {
  channels = [makeChannel()];
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  renderRoute('/o/acme/alerts/channels');
  expect(await screen.findByRole('button', { name: 'Add channel' })).toBeDisabled();
  expect(screen.getByRole('switch', { name: 'Enabled ops-webhook' })).toBeDisabled();
});

it('all-orgs channel read-only for non-admin', async () => {
  channels = [makeChannel({ allOrgs: true })];
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: org.id }]))));
  const { user } = renderRoute('/o/acme/alerts/channels');
  const sw = await screen.findByRole('switch', { name: 'Enabled ops-webhook' });
  expect(sw).toBeDisabled();
  await user.hover(sw);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs a global admin');
});

it('add disabled at 50', async () => {
  channels = Array.from({ length: 50 }, (_, i) => makeChannel({ id: `ch-${i}`, name: `ch-${i}` }));
  const { user } = renderRoute('/o/acme/alerts/channels');
  const btn = await screen.findByRole('button', { name: 'Add channel' });
  expect(btn).toBeDisabled();
  await user.hover(btn);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('at most 50 channels');
});

it('empty state', async () => {
  renderRoute('/o/acme/alerts/channels');
  expect(await screen.findByText('No channels yet.')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Add channel' })).toBeInTheDocument();
});
