import { http, HttpResponse } from 'msw';
import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { NotifyEvent } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, iso, makeEvent, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// Filters sit on the tab line from md; below it they fold into a popover.
beforeEach(() => {
  vi.stubGlobal('matchMedia', (query: string) => ({ matches: query === '(min-width: 768px)' || query === '(min-width: 1024px)', media: query, addEventListener: () => {}, removeEventListener: () => {} }));
});

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

it('renders a table newest first with severity, kind and summary', async () => {
  serveEvents([
    makeEvent({ id: 'ev-1', kind: 'cert.expired', severity: 'critical', summary: 'www.example.com expired' }),
    makeEvent({ id: 'ev-2', kind: 'cert.expiring', severity: 'warning', summary: 'api.example.com expires soon' }),
  ]);
  renderRoute('/o/acme/alerts/events');
  const list = await screen.findByRole('table', { name: 'Events' });
  const rows = await within(list).findAllByText(/Certificate expired|Certificate expiring/);
  expect(rows[0]).toHaveTextContent('Certificate expired');
  expect(rows[1]).toHaveTextContent('Certificate expiring');
  expect(within(list).getByText('Critical')).toBeInTheDocument();
  expect(within(list).getByText('Warning')).toBeInTheDocument();
  expect(within(list).getByText('www.example.com expired')).toBeInTheDocument();
  expect(within(list).getByText('api.example.com expires soon')).toBeInTheDocument();
});

function captureQuery() {
  const seen: { kind: string[]; severity: string | null; since: string | null } = { kind: [], severity: null, since: null };
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/events'), ({ request }) => {
      const q = new URL(request.url).searchParams;
      seen.kind = q.getAll('kind');
      seen.severity = q.get('severity');
      seen.since = q.get('since');
      return HttpResponse.json({ items: [], nextCursor: null });
    }),
  );
  return seen;
}

it('kind multi-select sets kind params and summarises the trigger', async () => {
  const seen = captureQuery();
  const { user } = renderRoute('/o/acme/alerts/events');
  const trigger = await screen.findByRole('combobox', { name: 'Kind' });
  expect(trigger).toHaveTextContent('All kinds');
  await user.click(trigger);
  expect(await screen.findByText('Deployments')).toBeInTheDocument();
  await user.click(await screen.findByRole('option', { name: /Deploy failed/ }));
  await waitFor(() => expect(seen.kind).toEqual(['deploy.failed']));
  expect(screen.getByRole('combobox', { name: 'Kind' })).toHaveTextContent('Deploy failed');
  await user.click(screen.getByRole('option', { name: /Drift/ }));
  await waitFor(() => expect(seen.kind).toEqual(['deploy.failed', 'deploy.drift']));
  expect(screen.getByRole('combobox', { name: 'Kind' })).toHaveTextContent('2 kinds');
});

it('a deep-linked kind shows as selected', async () => {
  serveEvents([]);
  renderRoute(`/o/acme/alerts/events?${kindSearch(['cert.issued', 'cert.expired'])}`);
  expect(await screen.findByRole('combobox', { name: 'Kind' })).toHaveTextContent('2 kinds');
});

it('severity combobox sets the minimum', async () => {
  const seen = captureQuery();
  const { user } = renderRoute('/o/acme/alerts/events');
  const trigger = await screen.findByRole('combobox', { name: 'Severity' });
  expect(trigger).toHaveTextContent('Any');
  await user.click(trigger);
  await user.click(await screen.findByRole('option', { name: 'Warning and above' }));
  await waitFor(() => expect(seen.severity).toBe('warning'));
  expect(screen.getByRole('combobox', { name: 'Severity' })).toHaveTextContent('Warning and above');
});

it('time combobox sends since and defaults to all time', async () => {
  const seen = captureQuery();
  const { user } = renderRoute('/o/acme/alerts/events');
  const trigger = await screen.findByRole('combobox', { name: 'Time' });
  expect(trigger).toHaveTextContent('All time');
  await waitFor(() => expect(seen.since).toBeNull());
  await user.click(trigger);
  await user.click(await screen.findByRole('option', { name: 'Last 7 days' }));
  await waitFor(() => expect(seen.since).not.toBeNull());
  const age = Date.now() - new Date(seen.since!).getTime();
  expect(Math.abs(age - 7 * 86_400_000)).toBeLessThan(120_000);
});

it('does not refetch repeatedly with a range set', async () => {
  let calls = 0;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/events'), () => {
      calls++;
      return HttpResponse.json({ items: [], nextCursor: null });
    }),
  );
  renderRoute('/o/acme/alerts/events?range=24h');
  await screen.findByText('No events match these filters.');
  await new Promise((r) => setTimeout(r, 200));
  expect(calls).toBe(1);
});

it('clear filters resets all three', async () => {
  const seen = captureQuery();
  const { user } = renderRoute(`/o/acme/alerts/events?${kindSearch(['cert.issued'])}&severity=critical&range=30d`);
  await waitFor(() => expect(seen.severity).toBe('critical'));
  await user.click(within(await screen.findByRole('search', { name: 'Filters' })).getByRole('button', { name: 'Clear filters' }));
  await waitFor(() => expect(seen.kind).toEqual([]));
  expect(seen.severity).toBeNull();
  expect(seen.since).toBeNull();
  expect(screen.getByRole('combobox', { name: 'Time' })).toHaveTextContent('All time');
});

const dlv = (id: string, status: 'pending' | 'delivered' | 'failed', extra: Partial<NotifyEvent['deliveries'][number]> = {}) => ({
  channelId: id, channelName: `chan-${id}`, status, attempts: 1, lastError: null, deliveredAt: null, ...extra,
});

it.each([
  ['one sent', [dlv('a', 'delivered')], 'Sent'],
  ['several sent', [dlv('a', 'delivered'), dlv('b', 'delivered')], '2 sent'],
  ['pending', [dlv('a', 'pending'), dlv('b', 'delivered'), dlv('c', 'pending')], '2 pending'],
  ['failed mix', [dlv('a', 'failed'), dlv('b', 'pending'), dlv('c', 'delivered'), dlv('d', 'delivered')], '1 of 4 failed'],
])('delivery summary: %s', async (_n, deliveries, label) => {
  serveEvents([makeEvent({ deliveries })]);
  renderRoute('/o/acme/alerts/events');
  expect(await screen.findByRole('button', { name: `Deliveries: ${label}` })).toHaveTextContent(label);
});

it('delivery summary popover lists every channel with attempts and error', async () => {
  serveEvents([
    makeEvent({ deliveries: [dlv('a', 'delivered', { channelName: 'ops-pager-production-primary', attempts: 1, deliveredAt: iso(0) }), dlv('b', 'failed', { channelName: 'ops-webhook', attempts: 2, lastError: 'connection refused' })] }),
  ]);
  const { user } = renderRoute('/o/acme/alerts/events');
  await user.click(await screen.findByRole('button', { name: 'Deliveries: 1 of 2 failed' }));
  const pop = await screen.findByText('ops-webhook');
  const content = pop.closest('[data-slot=popover-content]') as HTMLElement;
  expect(within(content).getByText('ops-pager-production-primary')).toBeInTheDocument();
  expect(content).toHaveTextContent('2 attempts');
  expect(content).toHaveTextContent('connection refused');
});

it('no matching channels reads None with a tooltip', async () => {
  serveEvents([makeEvent({ deliveries: [] })]);
  const { user } = renderRoute('/o/acme/alerts/events');
  const none = await screen.findByText('None');
  await user.hover(none);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('No channel matched this event.');
});

it('the below-lg card list uses the delivery summary', async () => {
  vi.stubGlobal('matchMedia', (query: string) => ({ matches: query === '(min-width: 768px)', media: query, addEventListener: () => {}, removeEventListener: () => {} }));
  serveEvents([makeEvent({ deliveries: [dlv('a', 'failed'), dlv('b', 'delivered')] })]);
  renderRoute('/o/acme/alerts/events');
  expect(await screen.findByRole('button', { name: 'Deliveries: 1 of 2 failed' })).toBeInTheDocument();
  expect(screen.queryByText('chan-a')).not.toBeInTheDocument();
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
  expect(await screen.findByLabelText('Global event')).toBeInTheDocument();
});

it('empty and filtered empty states', async () => {
  serveEvents([]);
  const { user } = renderRoute('/o/acme/alerts/events');
  expect(await screen.findByText('No events yet.')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Add channel' })).toHaveAttribute('href', '/o/acme/alerts/channels?edit=new');

  await user.click(screen.getByRole('combobox', { name: 'Severity' }));
  await user.click(await screen.findByRole('option', { name: 'Critical' }));
  expect(await screen.findByText('No events match these filters.')).toBeInTheDocument();
  await user.click(within(screen.getByRole('search', { name: 'Filters' })).getByRole('button', { name: 'Clear filters' }));
  expect(await screen.findByText('No events yet.')).toBeInTheDocument();
});

it('a deep-linked partial kind gives the filtered empty state and clears', async () => {
  serveEvents([]);
  const { user } = renderRoute(`/o/acme/alerts/events?${kindSearch(['cert.issued'])}`);
  expect(await screen.findByText('No events match these filters.')).toBeInTheDocument();
  expect(screen.getByRole('combobox', { name: 'Kind' })).toHaveTextContent('Certificate issued');
  await user.click(within(screen.getByRole('search', { name: 'Filters' })).getByRole('button', { name: 'Clear filters' }));
  expect(await screen.findByText('No events yet.')).toBeInTheDocument();
});

it('ignores an unsupported ?severity=info rather than counting it as an active filter', async () => {
  const seen: { severity: string | null } = { severity: 'unset' };
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/events'), ({ request }) => {
      seen.severity = new URL(request.url).searchParams.get('severity');
      return HttpResponse.json({ items: [], nextCursor: null });
    }),
  );
  renderRoute('/o/acme/alerts/events?severity=info');
  await waitFor(() => expect(seen.severity).toBeNull());
});
