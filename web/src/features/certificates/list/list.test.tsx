import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Certificate } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, ca, makeCert, meWith, problem, url } from '@/test/fixtures';
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

it('Import menu items link to import and upload', async () => {
  const { user } = renderRoute('/o/acme/certificates');
  await rowOf('www');
  await user.click(screen.getByRole('button', { name: 'Import' }));
  const menu = screen.getByRole('menu');
  expect(within(menu).getByRole('menuitem', { name: /acme\.sh or certbot/i })).toHaveAttribute('href', '/o/acme/certificates/import');
  expect(within(menu).getByRole('menuitem', { name: /Upload PEM or PKCS#12/i })).toHaveAttribute('href', '/o/acme/certificates/upload');
});

it('disables Import without certs:write', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: 'org-1' }]))));
  renderRoute('/o/acme/certificates');
  expect(await screen.findByRole('button', { name: 'Import' })).toBeDisabled();
});

it('shows Import in the header on the unfiltered empty state', async () => {
  all = [];
  renderRoute('/o/acme/certificates');
  await screen.findByText('No certificates yet.');
  expect(screen.getByRole('button', { name: 'Import' })).toBeInTheDocument();
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

// Fix round 1 (review, Important items 1-4) below.

it('keeps an externally applied q (saved view) synced to the input, and survives navigating back without the debounce reverting it', async () => {
  const { router, user } = renderRoute('/o/acme/certificates');
  await rowOf('www');
  await user.type(screen.getByRole('textbox', { name: 'Search certificates' }), 'api');
  await waitFor(() => expect(router.state.location.search).toEqual({ q: 'api' }));
  await user.click(screen.getByRole('button', { name: 'Save view' }));
  await user.type(screen.getByRole('textbox', { name: 'View name' }), 'API only');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await user.click(screen.getByRole('button', { name: 'Remove filter Search: api' }));
  await waitFor(() => expect(router.state.location.search).toEqual({}));

  // Apply the saved view: the URL and the input should both show q=api
  // immediately, without waiting for the (now-stale) debounce.
  await user.click(screen.getByRole('button', { name: 'API only' }));
  await waitFor(() => expect(router.state.location.search).toEqual({ q: 'api' }));
  expect(screen.getByRole('textbox', { name: 'Search certificates' })).toHaveValue('api');

  // Going back must not get silently reverted by a leftover debounce timer
  // still holding the old (pre-apply) typed value.
  router.history.back();
  await waitFor(() => expect(router.state.location.search).toEqual({}));
  await new Promise((r) => setTimeout(r, 300));
  expect(router.state.location.search).toEqual({});
});

it('shows an error state with Retry when the list fetch fails, then loads after retrying', async () => {
  let fail = true;
  server.use(
    http.get(url('/orgs/org-1/certificates'), () => {
      if (fail) return problem(500, 'boom');
      return HttpResponse.json({ items: all.slice(0, 3), nextCursor: null });
    }),
  );
  const { user } = renderRoute('/o/acme/certificates');
  expect(await screen.findByRole('button', { name: 'Retry' })).toBeInTheDocument();
  expect(screen.getByText(/boom/)).toBeInTheDocument();
  fail = false;
  await user.click(screen.getByRole('button', { name: 'Retry' }));
  await rowOf('www');
});

// Both loading-state tests gate the certificates response on a promise this
// test controls, so the pending state can be asserted deterministically —
// asserting immediately after `renderRoute` isn't reliable here, since
// auth's own `/auth/me` fetch resolves (and mounts the route) asynchronously
// too, and could race ahead of an ungated certificates fetch resolving as
// well by the time a query finds the table.
function gateCertificatesResponse() {
  let resolve!: () => void;
  const gate = new Promise<void>((r) => (resolve = r));
  server.use(
    http.get(url('/orgs/org-1/certificates'), async () => {
      await gate;
      return HttpResponse.json({ items: all.slice(0, 3), nextCursor: null });
    }),
  );
  return resolve;
}

it('renders loading rows inside the table while the list is pending', async () => {
  const resolve = gateCertificatesResponse();
  renderRoute('/o/acme/certificates');
  const table = await screen.findByRole('table', { name: 'Certificates' });
  expect(table).toHaveAttribute('aria-busy', 'true');
  // The skeleton rows are `aria-hidden` (decorative), so a DOM query
  // stands in for a role query here, which would only see the header row.
  expect(table.querySelectorAll('tbody tr').length).toBe(3);
  resolve();
  await rowOf('www');
});

it('shows card skeletons instead of a table while pending below 768px', async () => {
  stubViewport(false);
  const resolve = gateCertificatesResponse();
  renderRoute('/o/acme/certificates');
  expect(await screen.findByRole('status', { name: 'Loading certificates' })).toBeInTheDocument();
  expect(screen.queryByRole('table')).toBeNull();
  resolve();
  // The card `<Link>` wraps its whole card (name, status, validity, next
  // renewal), so its accessible name isn't the bare name `rowOf` expects.
  expect(await screen.findByRole('link', { name: /www/ })).toBeInTheDocument();
});

it('drops the cursor from the request when a filter changes after loading more', async () => {
  const { user } = renderRoute('/o/acme/certificates');
  await rowOf('www');
  await user.click(screen.getByRole('button', { name: 'Load more' }));
  await screen.findByRole('link', { name: 'vpn' });
  expect(lastQuery.get('cursor')).toBe('p2');
  await user.click(screen.getByRole('radio', { name: 'Failed' }));
  await waitFor(() => expect(lastQuery.get('status')).toBe('failed'));
  expect(lastQuery.get('cursor')).toBeNull();
});

it('deletes the selected certificates and clears the selection on the happy path', async () => {
  const deleted: string[] = [];
  server.use(
    http.delete(url('/orgs/org-1/certificates/:id'), ({ params }) => {
      deleted.push(params.id as string);
      return new HttpResponse(null, { status: 204 });
    }),
  );
  const { user } = renderRoute('/o/acme/certificates');
  await user.click(await rowOf('www'));
  await user.click(await rowOf('mail'));
  const bar = screen.getByRole('region', { name: 'Bulk actions' });
  await user.click(within(bar).getByRole('button', { name: 'Delete' }));
  const dialog = await screen.findByRole('dialog');
  expect(within(dialog).getByText('Delete 2 certificates')).toBeInTheDocument();
  await user.type(within(dialog).getByLabelText(/type delete to confirm/i), 'delete');
  await user.click(within(dialog).getByRole('button', { name: 'Delete' }));
  await waitFor(() => expect(deleted.sort()).toEqual(['c-1', 'c-3']));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  expect(screen.queryByRole('region', { name: 'Bulk actions' })).toBeNull();
});

it('keeps failed rows selected and names them in a toast on a partial bulk failure', async () => {
  server.use(
    http.post(url('/orgs/org-1/certificates/:id/renew'), ({ params }) => {
      const id = params.id as string;
      if (id === 'c-3') return problem(500, 'boom');
      renewed.push(id);
      return new HttpResponse(null, { status: 202 });
    }),
  );
  const { user } = renderRoute('/o/acme/certificates');
  await user.click(await rowOf('www'));
  await user.click(await rowOf('mail'));
  const bar = screen.getByRole('region', { name: 'Bulk actions' });
  await user.click(within(bar).getByRole('button', { name: 'Renew' }));
  await waitFor(() => expect(renewed).toEqual(['c-1']));
  // The failed row (mail, c-3) stays selected; the succeeded one (www) does not.
  await waitFor(() => expect(within(screen.getByRole('region', { name: 'Bulk actions' })).getByText('1 selected')).toBeInTheDocument());
  expect(await screen.findByText(/1 certificate failed: mail/)).toBeInTheDocument();
});

it('keeps the delete dialog open with its error on a total bulk failure', async () => {
  server.use(http.delete(url('/orgs/org-1/certificates/:id'), () => problem(500, 'boom')));
  const { user } = renderRoute('/o/acme/certificates');
  await user.click(await rowOf('www'));
  const bar = screen.getByRole('region', { name: 'Bulk actions' });
  await user.click(within(bar).getByRole('button', { name: 'Delete' }));
  const dialog = await screen.findByRole('dialog');
  await user.type(within(dialog).getByLabelText(/type delete to confirm/i), 'delete');
  await user.click(within(dialog).getByRole('button', { name: 'Delete' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent(/failed/i);
  expect(screen.getByRole('dialog')).toBeInTheDocument();
});

it('shows Revoked selected on the segmented control when the URL has status=revoked', async () => {
  all = [makeCert({ id: 'c-5', name: 'old', status: 'revoked' })];
  renderRoute('/o/acme/certificates?status=revoked');
  await rowOf('old');
  expect(screen.getByRole('radio', { name: 'Revoked', checked: true })).toBeInTheDocument();
});

it('tints the sticky Name cell to match the row when selected', async () => {
  const { user } = renderRoute('/o/acme/certificates');
  const row = await rowOf('www');
  const nameCell = within(row).getByText('www').closest('td')!;
  expect(nameCell.className).not.toContain('bg-primary/10');
  await user.click(row);
  expect(nameCell.className).toContain('bg-primary/10');
});

// Fix round 2 (Important #1): a viewer has certs:read but not certs:write
// or certs:issue — New certificate and the bulk Renew/Delete controls must
// stay visible but disabled (with a tooltip explaining why), not hidden or
// clickable.
it('disables New certificate and bulk Renew/Delete for a viewer', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: 'org-1' }]))));
  const { user } = renderRoute('/o/acme/certificates');
  expect(await screen.findByRole('button', { name: 'New certificate' })).toBeDisabled();
  await user.click(await rowOf('www'));
  const bar = screen.getByRole('region', { name: 'Bulk actions' });
  expect(within(bar).getByRole('button', { name: 'Renew' })).toBeDisabled();
  expect(within(bar).getByRole('button', { name: 'Delete' })).toBeDisabled();
});

it('shows how many clients hold each certificate', async () => {
  all = [makeCert({ id: 'c-1', name: 'www', grantCount: 3 }), makeCert({ id: 'c-2', name: 'api' })];
  renderRoute('/o/acme/certificates');
  const table = await screen.findByRole('table', { name: 'Certificates' });
  const www = within(table).getByRole('link', { name: 'www' }).closest('tr')!;
  expect(within(www).getByText('3')).toBeInTheDocument();
});
