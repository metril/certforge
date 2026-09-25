import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeAuditEvent, meWith, org, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';
import { saveBlob } from '@/lib/download';

vi.mock('@/lib/download', async (orig) => ({ ...(await orig<typeof import('@/lib/download')>()), saveBlob: vi.fn() }));

// Desktop by default (D5 mobile-card test overrides this), mirroring other
// list pages' viewport stub convention.
function stubViewport(isMdUp: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)' ? isMdUp : false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}
const ORIGINAL_INNER_WIDTH = window.innerWidth;
beforeEach(() => {
  stubViewport(true);
});
afterEach(() => {
  vi.unstubAllGlobals();
  window.innerWidth = ORIGINAL_INNER_WIDTH;
});

function capture() {
  const seen: URLSearchParams[] = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/audit'), ({ request }) => {
      seen.push(new URL(request.url).searchParams);
      return HttpResponse.json({
        items: [makeAuditEvent({ id: 7, action: 'settings.update', resourceType: 'settings', resourceId: 'general', orgId: null,
          details: { section: 'general', before: { baseUrl: 'http://a' }, after: { baseUrl: 'https://b' } } })],
        nextCursor: null,
      });
    }),
  );
  return seen;
}

it('opens an event with its before and after diff', async () => {
  capture();
  const { user, router } = renderRoute('/o/acme/audit');
  const table = await screen.findByRole('table', { name: 'Audit events' });
  await user.click(await within(table).findByText('settings.update'));
  const sheet = await screen.findByRole('dialog', { name: 'settings.update' });
  const changes = within(sheet).getByRole('table', { name: 'Changes' });
  expect(within(changes).getByText('"http://a"')).toBeInTheDocument();
  expect(within(changes).getByText('"https://b"')).toBeInTheDocument();
  expect(router.state.location.search).toMatchObject({ event: 7 });
});

it('sends URL filters to the API and shows them as chips', async () => {
  const seen = capture();
  const { user } = renderRoute('/o/acme/audit?action=session.&resourceType=user');
  await screen.findByRole('table', { name: 'Audit events' });
  const last = () => seen[seen.length - 1]!;
  expect(last().get('action')).toBe('session.');
  expect(last().get('resourceType')).toBe('user');
  expect(last().get('orgId')).toBe(org.id);
  await user.click(screen.getByRole('button', { name: 'Remove filter Action: session.*' }));
  await waitFor(() => expect(last().has('action')).toBe(false));
});

it('survives a bad URL', async () => {
  const seen = capture();
  renderRoute('/o/acme/audit?from=yesterday&action=%00&to=2020-01-01&event=nope');
  await screen.findByRole('heading', { name: 'Audit log' });
  const q = seen[seen.length - 1]!;
  expect(q.has('from')).toBe(false);
  expect(q.has('action')).toBe(false);
  expect(q.get('to')).toMatch(/^2020-01-0[12]T/);
});

it('keeps an inverted date range visible and sends it', async () => {
  const seen = capture();
  renderRoute('/o/acme/audit?from=2030-01-01&to=2020-01-01');
  expect(await screen.findByText('From 2030-01-01')).toBeInTheDocument();
  expect(screen.getByText('To 2020-01-01')).toBeInTheDocument();
  expect(seen[seen.length - 1]!.has('from')).toBe(true);
});

it('shows a broken chain', async () => {
  capture();
  server.use(http.get(url('/audit/verify'), () =>
    HttpResponse.json({ ok: false, count: 41, brokenAtId: 42, checkedAt: '2026-09-24T12:00:00Z', headHash: 'ab' })));
  renderRoute('/o/acme/audit');
  expect(await screen.findByText('Chain broken at #42')).toBeInTheDocument();
});

it('exports the filtered events as CSV', async () => {
  capture();
  let exported: URLSearchParams | undefined;
  server.use(http.get(url('/audit/export'), ({ request }) => {
    exported = new URL(request.url).searchParams;
    return new HttpResponse('id,ts\n', { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="audit-2026-09-24.csv"' } });
  }));
  const { user } = renderRoute('/o/acme/audit?action=certificate.renew');
  await user.click(await screen.findByRole('button', { name: 'Export CSV' }));
  await waitFor(() => expect(saveBlob).toHaveBeenCalledWith(expect.any(Blob), 'audit-2026-09-24.csv'));
  expect(exported?.get('action')).toBe('certificate.renew');
  expect(exported?.get('orgId')).toBe(org.id);
});

// The export cap notice (X-Audit-Truncated) shows once, after the download.
it('shows a one-line notice when the export was truncated', async () => {
  capture();
  server.use(http.get(url('/audit/export'), () =>
    new HttpResponse('id,ts\n', { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="audit-2026-09-24.csv"', 'X-Audit-Truncated': 'true' } })));
  const { user } = renderRoute('/o/acme/audit');
  await user.click(await screen.findByRole('button', { name: 'Export CSV' }));
  expect(await screen.findByText(/100,000-row cap/)).toBeInTheDocument();
});

it('tells a viewer the log is out of reach', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))),
  );
  renderRoute('/o/acme/audit');
  expect(await screen.findByText("Your role can't read the audit log here.")).toBeInTheDocument();
});

// C10: a deep link's ?event isn't in the loaded page, so the sheet is
// opened from a direct GET /audit/{id} instead.
it('opens a deep-linked event that is not in the loaded page', async () => {
  capture();
  server.use(http.get(url('/audit/9'), () =>
    HttpResponse.json(makeAuditEvent({ id: 9, action: 'certificate.renew', orgId: org.id }))));
  renderRoute('/o/acme/audit?event=9');
  const sheet = await screen.findByRole('dialog', { name: 'certificate.renew' });
  expect(within(sheet).getByText('#9')).toBeInTheDocument();
});

// C10: a 404 (missing, or not visible to the caller) shows an inline
// one-line notice and clears the `event` param instead of leaving a
// perpetually-loading sheet.
it('shows an inline notice and clears the param for a deep link that 404s', async () => {
  capture();
  server.use(http.get(url('/audit/404'), () => new HttpResponse(null, { status: 404 })));
  const { router } = renderRoute('/o/acme/audit?event=404');
  await screen.findByRole('table', { name: 'Audit events' });
  expect(await screen.findByText("That event doesn't exist or isn't visible to you.")).toBeInTheDocument();
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('event'));
});

// D5: card rows below 768px, no horizontal overflow at 375px.
it('shows card rows instead of a table below 768px with no horizontal overflow', async () => {
  stubViewport(false);
  window.innerWidth = 375;
  capture();
  const { container } = renderRoute('/o/acme/audit');
  await screen.findByText('settings.update');
  expect(screen.queryByRole('table')).toBeNull();
  expect(container.querySelector('[class*="min-w-["]')).toBeNull();
  expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(window.innerWidth);
});
