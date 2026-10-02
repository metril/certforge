import { http, HttpResponse } from 'msw';
import { act, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Client } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, iso, makeClient, makeSite, meWith, NOW, org, org2, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let lastQuery: URLSearchParams | undefined;
let items: Client[];

function stubViewport(isMdUp: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)' ? isMdUp : false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}

const rowOf = (table: HTMLElement, name: string) => within(table).getByText(name).closest('tr')!;

// findByRole also matches the loading skeleton (same aria-label, no row
// text yet), so a synchronous rowOf right after it can race the fetch;
// wait for the skeleton's aria-busy to clear before reading row content.
async function findLoadedTable(name: string) {
  const table = await screen.findByRole('table', { name });
  await waitFor(() => expect(table).not.toHaveAttribute('aria-busy', 'true'));
  return table;
}

beforeEach(() => {
  stubViewport(true);
  // Reset so a leftover value from a previous test can never make a
  // not-yet-sent request's assertion pass by accident.
  lastQuery = undefined;
  items = [
    makeClient({ id: 'cl-1', name: 'web-1', siteId: 's-1', driftCount: 2 }),
    makeClient({ id: 'cl-2', name: 'db-1', connected: false, online: false, lastSeen: iso(-1), failedCount: 1 }),
    makeClient({ id: 'cl-3', name: 'new-host', status: 'pending', connected: false, online: false, lastSeen: null, hostname: '', agentVersion: '', grantCount: 0 }),
  ];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/sites'), () => HttpResponse.json({ items: [makeSite({ id: 's-1', name: 'Rack A' })] })),
    http.get(url('/orgs/org-1/clients'), ({ request }) => {
      lastQuery = new URL(request.url).searchParams;
      return HttpResponse.json({ items, nextCursor: null });
    }),
  );
});

it('lists clients with status, connection, site, agent, grants, drift and last seen', async () => {
  renderRoute('/o/acme/clients');
  const table = await findLoadedTable('Clients');
  const web = rowOf(table, 'web-1');
  expect(within(web).getByText('Active')).toBeInTheDocument();
  expect(within(web).getByText('Online')).toBeInTheDocument();
  expect(within(web).getByText(/Rack A/)).toBeInTheDocument();
  expect(within(web).getByText(/agent 0.3.0/)).toBeInTheDocument();
  expect(within(web).getByText(/2 drift/)).toBeInTheDocument();
  expect(within(rowOf(table, 'db-1')).getByText('Offline')).toBeInTheDocument();
  expect(within(rowOf(table, 'db-1')).getByText(/1 failed/)).toBeInTheDocument();
  const pending = rowOf(table, 'new-host');
  expect(within(pending).getByText('Pending')).toBeInTheDocument();
  expect(within(pending).getByText('Never connected')).toBeInTheDocument();
  expect(within(pending).getByText('Never')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Enrol client' })).toHaveAttribute('href', '/o/acme/clients/new');
});

it('shows a pull-only client seen 30 s ago as Online', async () => {
  items = [makeClient({ id: 'cl-4', name: 'cron-1', connected: false, online: true, lastSeen: new Date(NOW - 30_000).toISOString() })];
  renderRoute('/o/acme/clients');
  const table = await findLoadedTable('Clients');
  expect(within(rowOf(table, 'cron-1')).getByText('Online')).toBeInTheDocument();
});

it('sends URL filters and sort, and filters by status and site', async () => {
  const { user, router } = renderRoute('/o/acme/clients?sort=-lastSeen');
  await findLoadedTable('Clients');
  await waitFor(() => expect(lastQuery?.get('sort')).toBe('-lastSeen'));
  await user.click(screen.getByRole('radio', { name: 'Pending' }));
  await waitFor(() => expect(lastQuery?.get('status')).toBe('pending'));
  await user.click(screen.getByRole('combobox', { name: 'Site' }));
  await user.click(await screen.findByRole('option', { name: 'Rack A' }));
  await waitFor(() => expect(lastQuery?.get('site')).toBe('s-1'));
  expect(router.state.location.search).toMatchObject({ status: 'pending', site: 's-1', sort: '-lastSeen' });
  await user.click(screen.getByRole('button', { name: 'Remove filter Site: Rack A' }));
  await waitFor(() => expect(lastQuery?.get('site')).toBeNull());
});

it('survives a bad URL', async () => {
  renderRoute(`/o/acme/clients?status=bogus&site=%00&sort=evil&q=${'x'.repeat(201)}`);
  await findLoadedTable('Clients');
  await waitFor(() => expect(lastQuery).toBeDefined());
  expect(lastQuery?.get('status')).toBeNull();
  expect(lastQuery?.get('site')).toBeNull();
  expect(lastQuery?.get('sort')).toBeNull();
  expect(lastQuery?.get('q')).toBeNull();
});

it('stale cursor: resets to the first page', async () => {
  server.use(
    http.get(url('/orgs/org-1/clients'), ({ request }) =>
      new URL(request.url).searchParams.get('cursor') ? problem(422, 'cursor does not match this request') : HttpResponse.json({ items, nextCursor: 'next' }),
    ),
  );
  const { user } = renderRoute('/o/acme/clients');
  const table = await findLoadedTable('Clients');
  rowOf(table, 'web-1');
  await user.click(screen.getByRole('button', { name: 'Load more' }));
  expect(await screen.findByText('The list changed since it was loaded; showing the first page again.')).toBeInTheDocument();
  // The reset itself re-fetches page one (no cursor), so the same rows
  // that were showing before "Load more" are still there afterwards, not
  // an empty or half-populated list.
  await waitFor(() => expect(rowOf(screen.getByRole('table', { name: 'Clients' }), 'web-1')).toBeInTheDocument());
});

it('shows the stale-cursor notice from a background refetch too, not only a Load more click', async () => {
  // M6: the notice used to depend on `loadMore`'s own explicit 422 check;
  // a background refetch that lands the same 422 (the list polls every 30s)
  // now shows it too, through a plain effect on `list.error`, and keeps
  // whatever rows are already on screen instead of clearing them.
  let pageTwoCalls = 0;
  server.use(
    http.get(url('/orgs/org-1/clients'), ({ request }) => {
      const cursor = new URL(request.url).searchParams.get('cursor');
      if (!cursor) return HttpResponse.json({ items, nextCursor: 'next' });
      pageTwoCalls += 1;
      return pageTwoCalls === 1
        ? HttpResponse.json({ items: [makeClient({ id: 'cl-9', name: 'extra' })], nextCursor: null })
        : problem(422, 'cursor does not match this request');
    }),
  );
  const { queryClient, user } = renderRoute('/o/acme/clients');
  const table = await findLoadedTable('Clients');
  rowOf(table, 'web-1');
  await user.click(screen.getByRole('button', { name: 'Load more' }));
  await screen.findByText('extra');
  // A background refetch (e.g. the list's own 30 s poll), not a Load more
  // click, is what re-requests the now-stale second page here.
  await act(() => queryClient.refetchQueries({ queryKey: ['clients', 'org-1', 'list'] }));
  expect(await screen.findByText('The list changed since it was loaded; showing the first page again.')).toBeInTheDocument();
  expect(rowOf(screen.getByRole('table', { name: 'Clients' }), 'web-1')).toBeInTheDocument();
});

it('shows one sentence and Enrol client when empty; a viewer gets it disabled', async () => {
  items = [];
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  renderRoute('/o/acme/clients');
  expect(await screen.findByText('No clients yet.')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Enrol client' })).toBeDisabled();
});

it('renders card rows below md', async () => {
  stubViewport(false);
  renderRoute('/o/acme/clients');
  expect(await screen.findByText('web-1')).toBeInTheDocument();
  expect(screen.queryByRole('table')).not.toBeInTheDocument();
  expect(screen.getByText('Seen just now')).toBeInTheDocument();
});

it('lists every org read-only under All orgs', async () => {
  let hit = false;
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'admin', orgId: null }], [org, org2]))),
    http.get(url('/clients'), () => {
      hit = true;
      return HttpResponse.json({ items: [makeClient({ orgId: org2.id, name: 'lab-1' })], nextCursor: null });
    }),
  );
  renderRoute('/o/all/clients');
  const table = await findLoadedTable('Clients');
  expect(hit).toBe(true);
  expect(within(rowOf(table, 'lab-1')).getByText('Lab')).toBeInTheDocument();
  expect(screen.queryByRole('link', { name: 'Enrol client' })).not.toBeInTheDocument();
  expect(screen.queryByRole('combobox', { name: 'Site' })).not.toBeInTheDocument();
});

it('links each row to its client', async () => {
  renderRoute('/o/acme/clients');
  const table = await findLoadedTable('Clients');
  expect(within(table).getByRole('link', { name: 'web-1' })).toHaveAttribute('href', '/o/acme/clients/cl-1');
});
