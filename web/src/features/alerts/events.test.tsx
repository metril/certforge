import { http, HttpResponse } from 'msw';
import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { NotifyEvent } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, iso, makeEvent, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// Filters sit on the tab line from md; below it they fold into a popover.
beforeEach(() => {
  vi.stubGlobal('matchMedia', (query: string) => ({ matches: query === '(min-width: 768px)', media: query, addEventListener: () => {}, removeEventListener: () => {} }));
});

const CERT_KINDS = ['cert.issued', 'cert.renewal_failed', 'cert.expiring', 'cert.expired'];

/** A `kind` deep link the way TanStack Router's own default search
 * serialization actually round-trips an array: a lone `?kind=cert.issued`
 * (no repeated key) decodes to the bare string "cert.issued", not an
 * array, and fails `z.array(eventKind)` — the router only rebuilds an array
 * from either repeated keys or this JSON form. */
function kindSearch(kinds: string[]): string {
  return `kind=${encodeURIComponent(JSON.stringify(kinds))}`;
}

function serveEvents(items: NotifyEvent[], nextCursor: string | null = null) {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/events'), () => HttpResponse.json({ items, nextCursor })),
  );
}

it('renders newest first with severity, kind and summary', async () => {
  serveEvents([
    makeEvent({ id: 'ev-1', kind: 'cert.expired', severity: 'critical', summary: 'www.example.com expired' }),
    makeEvent({ id: 'ev-2', kind: 'cert.expiring', severity: 'warning', summary: 'api.example.com expires soon' }),
  ]);
  renderRoute('/o/acme/alerts/events');
  const list = await screen.findByRole('list', { name: 'Events' });
  const rows = await within(list).findAllByText(/Certificate expired|Certificate expiring/);
  expect(rows[0]).toHaveTextContent('Certificate expired');
  expect(rows[1]).toHaveTextContent('Certificate expiring');
  expect(within(list).getByText('Critical')).toBeInTheDocument();
  expect(within(list).getByText('Warning')).toBeInTheDocument();
  expect(within(list).getByText('www.example.com expired')).toBeInTheDocument();
  expect(within(list).getByText('api.example.com expires soon')).toBeInTheDocument();
});

it('group chip sets kind params', async () => {
  let seen: string[] = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/events'), ({ request }) => {
      seen = new URL(request.url).searchParams.getAll('kind');
      return HttpResponse.json({ items: [], nextCursor: null });
    }),
  );
  const { user } = renderRoute('/o/acme/alerts/events');
  const toolbar = await screen.findByRole('toolbar', { name: 'Event groups' });
  await user.click(within(toolbar).getByRole('button', { name: 'Certificates' }));
  await waitFor(() => expect(seen).toEqual(CERT_KINDS));
});

it('partial group from URL is not filled', async () => {
  serveEvents([]);
  renderRoute(`/o/acme/alerts/events?${kindSearch(['cert.issued'])}`);
  const toolbar = await screen.findByRole('toolbar', { name: 'Event groups' });
  expect(within(toolbar).getByRole('button', { name: 'Certificates' })).toHaveAttribute('aria-pressed', 'false');
});

it('severity segmented sets minimum', async () => {
  let seen: string | null = 'unset';
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/events'), ({ request }) => {
      seen = new URL(request.url).searchParams.get('severity');
      return HttpResponse.json({ items: [], nextCursor: null });
    }),
  );
  const { user } = renderRoute('/o/acme/alerts/events');
  expect(await screen.findByRole('radio', { name: 'All' })).toHaveAttribute('aria-checked', 'true');
  await user.click(screen.getByRole('radio', { name: 'Warning+' }));
  await waitFor(() => expect(seen).toBe('warning'));
});

it('delivery chip tooltip shows attempts and error', async () => {
  serveEvents([
    makeEvent({ deliveries: [{ channelId: 'c-1', channelName: 'ops-webhook', status: 'failed', attempts: 2, lastError: 'connection refused', deliveredAt: null }] }),
  ]);
  const { user } = renderRoute('/o/acme/alerts/events');
  const chip = await screen.findByText('ops-webhook');
  await user.hover(chip);
  const tooltip = await screen.findByRole('tooltip');
  expect(tooltip).toHaveTextContent('2 attempts');
  expect(tooltip).toHaveTextContent('connection refused');
});

it('no matching channels', async () => {
  serveEvents([makeEvent({ deliveries: [] })]);
  renderRoute('/o/acme/alerts/events');
  expect(await screen.findByText('No matching channels')).toBeInTheDocument();
});

it('load more follows cursor', async () => {
  let cursorSeen: string | null = null;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/events'), ({ request }) => {
      const cursor = new URL(request.url).searchParams.get('cursor');
      cursorSeen = cursor;
      if (cursor === 'c2') return HttpResponse.json({ items: [makeEvent({ id: 'ev-2', summary: 'second page event' })], nextCursor: null });
      return HttpResponse.json({ items: [makeEvent({ id: 'ev-1', summary: 'first page event' })], nextCursor: 'c2' });
    }),
  );
  const { user } = renderRoute('/o/acme/alerts/events');
  expect(await screen.findByText('first page event')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Load more' }));
  await waitFor(() => expect(cursorSeen).toBe('c2'));
  expect(await screen.findByText('second page event')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
});

afterEach(() => vi.useRealTimers());

it('polls only while pending', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] });
  let calls = 0;
  let status: 'pending' | 'delivered' = 'pending';
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/events'), () => {
      calls++;
      return HttpResponse.json({
        items: [makeEvent({ deliveries: [{ channelId: 'c-1', channelName: 'ops', status, attempts: 1, lastError: null, deliveredAt: status === 'delivered' ? iso(0) : null }] })],
        nextCursor: null,
      });
    }),
  );
  renderRoute('/o/acme/alerts/events');
  await act(async () => { await vi.advanceTimersByTimeAsync(50); });
  const first = calls;
  await act(async () => { await vi.advanceTimersByTimeAsync(5_050); });
  expect(calls).toBe(first + 1);

  status = 'delivered';
  await act(async () => { await vi.advanceTimersByTimeAsync(5_050); });
  const settled = calls;
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(calls).toBe(settled);
});

it('resource links by type', async () => {
  serveEvents([
    makeEvent({ id: 'ev-cert', resource: { type: 'certificate', id: 'cert-1', name: 'www.example.com' } }),
    makeEvent({ id: 'ev-client', kind: 'client.offline', resource: { type: 'client', id: 'client-1', name: 'edge-01' } }),
    makeEvent({ id: 'ev-monitor', kind: 'monitor.mismatch', resource: { type: 'monitor', id: 'mon-1', name: 'edge' } }),
    makeEvent({ id: 'ev-channel', kind: 'test', resource: { type: 'channel', id: 'ch-1', name: 'ops-webhook' } }),
    makeEvent({ id: 'ev-backup', kind: 'backup.completed', orgId: null, resource: { type: 'backup', id: 'b-1', name: 'certforge-20260101T000000Z.cfbak' } }),
    makeEvent({ id: 'ev-grant', kind: 'deploy.failed', resource: { type: 'grant', id: 'g-1', name: 'www -> edge-01' } }),
  ]);
  renderRoute('/o/acme/alerts/events');
  expect(await screen.findByRole('link', { name: 'www.example.com' })).toHaveAttribute('href', '/o/acme/certificates/cert-1/overview');
  expect(screen.getByRole('link', { name: 'edge-01' })).toHaveAttribute('href', '/o/acme/clients/client-1');
  expect(screen.getByRole('link', { name: 'edge' })).toHaveAttribute('href', '/o/acme/alerts/monitors?edit=mon-1');
  expect(screen.getByRole('link', { name: 'ops-webhook' })).toHaveAttribute('href', '/o/acme/alerts/channels?edit=ch-1');
  expect(screen.getByRole('link', { name: 'certforge-20260101T000000Z.cfbak' })).toHaveAttribute('href', '/settings/backup');
  expect(screen.getByText('www -> edge-01')).toBeInTheDocument();
  expect(screen.queryByRole('link', { name: 'www -> edge-01' })).not.toBeInTheDocument();
});

it('global event chip', async () => {
  serveEvents([makeEvent({ orgId: null, kind: 'backup.completed', resource: { type: 'backup', id: 'b-1', name: 'certforge-20260101T000000Z.cfbak' } })]);
  renderRoute('/o/acme/alerts/events');
  expect(await screen.findByText('Global')).toBeInTheDocument();
});

it('empty and filtered empty states', async () => {
  serveEvents([]);
  const { user } = renderRoute('/o/acme/alerts/events');
  expect(await screen.findByText('No events yet.')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Add channel' })).toHaveAttribute('href', '/o/acme/alerts/channels?edit=new');

  const toolbar = await screen.findByRole('toolbar', { name: 'Event groups' });
  await user.click(within(toolbar).getByRole('button', { name: 'Certificates' }));
  expect(await screen.findByText('No events match these filters.')).toBeInTheDocument();
  await user.click(within(screen.getByRole('search', { name: 'Filters' })).getByRole('button', { name: 'Clear filters' }));
  expect(await screen.findByText('No events yet.')).toBeInTheDocument();
});

// Batch 2 review: a deep-linked partial `?kind` (not a full group) used to
// filter the list while showing no chip and no way to clear it, and its
// empty result read as the unfiltered "No events yet." instead of "No
// events match these filters.".
it('a deep-linked partial kind shows a removable chip and the filtered empty state', async () => {
  serveEvents([]);
  const { user } = renderRoute(`/o/acme/alerts/events?${kindSearch(['cert.issued'])}`);
  expect(await screen.findByText('No events match these filters.')).toBeInTheDocument();
  // Desktop: no chip echo; the toolbar's Clear filters resets it.
  expect(screen.queryByRole('button', { name: 'Remove filter Certificate issued' })).not.toBeInTheDocument();
  await user.click(within(screen.getByRole('search', { name: 'Filters' })).getByRole('button', { name: 'Clear filters' }));
  expect(await screen.findByText('No events yet.')).toBeInTheDocument();
});

// A leftover kind outside any full group must survive an unrelated group
// toggle (toggleGroups only adds/removes the group that actually changed).
it('toggling a group keeps a leftover kind from the URL', async () => {
  let seen: string[] = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/events'), ({ request }) => {
      seen = new URL(request.url).searchParams.getAll('kind');
      return HttpResponse.json({ items: [], nextCursor: null });
    }),
  );
  const { user } = renderRoute(`/o/acme/alerts/events?${kindSearch(['cert.issued'])}`);
  const toolbar = await screen.findByRole('toolbar', { name: 'Event groups' });
  await user.click(within(toolbar).getByRole('button', { name: 'Deployments' }));
  await waitFor(() => expect(seen).toEqual(['cert.issued', 'deploy.failed', 'deploy.drift']));
});
