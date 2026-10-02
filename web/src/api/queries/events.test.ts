import { QueryClient } from '@tanstack/react-query';
import { http, HttpResponse } from 'msw';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { makeEvent, url } from '@/test/fixtures';
import { eventsQuery } from './events';

it('repeats kind params', async () => {
  let seen: string[] = [];
  server.use(
    http.get(url('/orgs/:orgId/events'), ({ request }) => {
      seen = new URL(request.url).searchParams.getAll('kind');
      return HttpResponse.json({ items: [], nextCursor: null });
    }),
  );
  const qc = new QueryClient();
  await qc.fetchInfiniteQuery(eventsQuery('org-1', { kind: ['cert.issued', 'monitor.mismatch'] }));
  expect(seen).toEqual(['cert.issued', 'monitor.mismatch']);
});

it('sends since', async () => {
  let seen: string | null = null;
  server.use(
    http.get(url('/orgs/:orgId/events'), ({ request }) => {
      seen = new URL(request.url).searchParams.get('since');
      return HttpResponse.json({ items: [], nextCursor: null });
    }),
  );
  const qc = new QueryClient();
  await qc.fetchInfiniteQuery(eventsQuery('org-1', { since: '2026-01-01T00:00:00.000Z' }));
  expect(seen).toBe('2026-01-01T00:00:00.000Z');
});

it('follows next cursor', async () => {
  const pages = [
    { items: [makeEvent({ id: 'ev-1' })], nextCursor: 'c2' },
    { items: [makeEvent({ id: 'ev-2' })], nextCursor: null },
  ];
  server.use(
    http.get(url('/orgs/:orgId/events'), ({ request }) => {
      const cursor = new URL(request.url).searchParams.get('cursor');
      return HttpResponse.json(cursor === 'c2' ? pages[1] : pages[0]);
    }),
  );
  const qc = new QueryClient();
  const opts = eventsQuery('org-1', {});
  const page1 = await qc.fetchInfiniteQuery(opts);
  const next = opts.getNextPageParam(page1.pages[0]!, page1.pages, undefined, []);
  expect(next).toBe('c2');
});

it('polls only while a loaded delivery is pending', () => {
  const opts = eventsQuery('org-1', {});
  const pendingState = { data: { pages: [{ items: [makeEvent({ deliveries: [{ channelId: 'c', channelName: 'c', status: 'pending', attempts: 1, lastError: null, deliveredAt: null }] })], pageParams: [undefined] } as never] } } as never;
  const settledState = { data: { pages: [{ items: [makeEvent({ deliveries: [{ channelId: 'c', channelName: 'c', status: 'delivered', attempts: 1, lastError: null, deliveredAt: '2026-01-01T00:00:00Z' }] })], pageParams: [undefined] } as never] } } as never;
  const refetch = opts.refetchInterval as (q: unknown) => number | false;
  expect(refetch({ state: pendingState })).toBe(5000);
  expect(refetch({ state: settledState })).toBe(false);
});
