import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Certificate } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, ca, makeCert, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let all: Certificate[];
let lastQuery: URLSearchParams;
let renewed: string[];

// A controllable `matchMedia` mock, matching AppShell.test.tsx's convention:
// only the `(min-width: 768px)` query (the one CertificatesPage checks for
// card rows, preflight D9) is meaningful here.
function stubViewport(isMdUp: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)' ? isMdUp : false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}

beforeEach(() => {
  all = [
    makeCert({ id: 'c-1', name: 'www' }),
    makeCert({ id: 'c-2', name: 'api', status: 'failed' }),
    makeCert({ id: 'c-3', name: 'mail' }),
    makeCert({ id: 'c-4', name: 'vpn' }),
  ];
  renewed = [];
  // Desktop by default so the existing table-oriented assertions below hold;
  // the card-rows test overrides this with stubViewport(false).
  stubViewport(true);
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca])),
    http.get(url('/orgs/org-1/certificates'), ({ request }) => {
      lastQuery = new URL(request.url).searchParams;
      const status = lastQuery.get('status');
      const items = all.filter((c) => !status || c.status === status);
      if (lastQuery.get('cursor') === 'p2') return HttpResponse.json({ items: items.slice(3), nextCursor: null });
      return HttpResponse.json({ items: items.slice(0, 3), nextCursor: items.length > 3 ? 'p2' : null });
    }),
    http.post(url('/orgs/org-1/certificates/:id/renew'), ({ params }) => {
      renewed.push(params.id as string);
      return new HttpResponse(null, { status: 202 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const rowOf = async (name: string) => (await screen.findByRole('link', { name })).closest('tr')!;

it('renders status chips and validity bars', async () => {
  renderRoute('/o/acme/certificates');
  const row = await rowOf('www');
  expect(within(row).getByText('Active')).toBeInTheDocument();
  expect(within(row).getByRole('img', { name: /^Valid .* to / })).toBeInTheDocument();
  expect(within(row).getByText('in 60 d')).toBeInTheDocument();
});

it('syncs the status filter to the URL and the request, with a removable chip', async () => {
  const { router, user } = renderRoute('/o/acme/certificates');
  await rowOf('www');
  await user.click(screen.getByRole('radio', { name: 'Failed' }));
  await waitFor(() => expect(router.state.location.search).toEqual({ status: 'failed' }));
  await waitFor(() => expect(lastQuery.get('status')).toBe('failed'));
  expect(await screen.findByRole('link', { name: 'api' })).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Remove filter Status: Failed' }));
  await waitFor(() => expect(router.state.location.search).toEqual({}));
});

it('selects rows with click and shift-click, then renews in bulk', async () => {
  const { user } = renderRoute('/o/acme/certificates');
  await user.click(await rowOf('www'));
  await user.keyboard('{Shift>}');
  await user.click(await rowOf('mail'));
  await user.keyboard('{/Shift}');
  const bar = screen.getByRole('region', { name: 'Bulk actions' });
  expect(within(bar).getByText('3 selected')).toBeInTheDocument();
  await user.click(within(bar).getByRole('button', { name: 'Renew' }));
  await waitFor(() => expect(renewed.sort()).toEqual(['c-1', 'c-2', 'c-3']));
});

it('loads the next page with the cursor', async () => {
  const { user } = renderRoute('/o/acme/certificates');
  await rowOf('www');
  await user.click(screen.getByRole('button', { name: 'Load more' }));
  expect(await screen.findByRole('link', { name: 'vpn' })).toBeInTheDocument();
});

it('shows one sentence and one button when there are no certificates', async () => {
  all = [];
  renderRoute('/o/acme/certificates');
  expect(await screen.findByText('No certificates yet.')).toBeInTheDocument();
  expect(screen.getAllByRole('link', { name: 'New certificate' })).toHaveLength(1);
});

// Additional coverage beyond the brief's literal Step 1 tests, required by
// the controller ruling (D9: card rows below md; the 422/stale-cursor and
// blocked-storage rules under "Cross-cutting patterns" and "Saved views").

it('shows card rows instead of a table below 768px', async () => {
  stubViewport(false);
  renderRoute('/o/acme/certificates');
  const card = await screen.findByRole('link', { name: /www/ });
  expect(screen.queryByRole('table')).toBeNull();
  expect(within(card).getByText('Active')).toBeInTheDocument();
  expect(within(card).getByRole('img', { name: /^Valid .* to / })).toBeInTheDocument();
  expect(within(card).getByText('in 30 d')).toBeInTheDocument();
});

it('resets to the first page and shows a notice when a cursor 422s', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates'), ({ request }) => {
      const q = new URL(request.url).searchParams;
      if (q.get('cursor') === 'p2') return problem(422, 'Cursor no longer matches these filters.');
      return HttpResponse.json({ items: all.slice(0, 3), nextCursor: 'p2' });
    }),
  );
  const { user } = renderRoute('/o/acme/certificates');
  await rowOf('www');
  await user.click(screen.getByRole('button', { name: 'Load more' }));
  expect(await screen.findByText(/showing the first page again/i)).toBeInTheDocument();
  expect(await screen.findByRole('link', { name: 'www' })).toBeInTheDocument();
});

it('saves a view under a blocked localStorage without losing it across the same session, but not across a reload', async () => {
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error('blocked');
  });
  const { user, unmount } = renderRoute('/o/acme/certificates');
  await rowOf('www');
  await user.click(screen.getByRole('radio', { name: 'Failed' }));
  await screen.findByRole('link', { name: 'api' });
  await user.click(screen.getByRole('button', { name: 'Save view' }));
  await user.type(screen.getByRole('textbox', { name: 'View name' }), 'Failing');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  expect(screen.getByRole('button', { name: 'Failing' })).toBeInTheDocument();
  unmount();
  renderRoute('/o/acme/certificates');
  await rowOf('www');
  expect(screen.queryByRole('button', { name: 'Failing' })).toBeNull();
});
