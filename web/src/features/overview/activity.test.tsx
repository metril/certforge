import { http, HttpResponse } from 'msw';
import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, iso, makeAuditEvent, makeCert, meWith, NOW, org, org2, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

afterEach(() => vi.useRealTimers());

// Recent activity is the second tab of the Overview's insights card.
async function openActivity(user: ReturnType<typeof renderRoute>['user']) {
  await user.click(await screen.findByRole('tab', { name: 'Recent activity' }));
  return screen.findByRole('region', { name: 'Recent activity' });
}

it('shows the last 20 events for the org', async () => {
  let query: URLSearchParams | undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/audit'), ({ request }) => {
      query = new URL(request.url).searchParams;
      return HttpResponse.json({ items: [makeAuditEvent({ id: 3, action: 'certificate.renew' }), makeAuditEvent({ id: 2, action: 'ca.create', actorName: 'Ann' })], nextCursor: null });
    }),
  );
  const { user } = renderRoute('/o/acme/overview');
  const region = await openActivity(user);
  expect(await within(region).findByRole('link', { name: 'certificate.renew' })).toHaveAttribute('href', '/o/acme/audit?event=3');
  expect(within(region).getByText('Ann')).toBeInTheDocument();
  expect(query?.get('orgId')).toBe(org.id);
  expect(query?.get('limit')).toBe('20');
});

it('is hidden without audit:read', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))),
    http.get(url('/orgs/:orgId/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
  );
  renderRoute('/o/acme/overview');
  await screen.findByRole('region', { name: 'Upcoming renewals' });
  expect(screen.queryByRole('tab', { name: 'Recent activity' })).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Recent activity' })).not.toBeInTheDocument();
});

// Fix round 2 (Important #2): an auditor has audit:read but not users:read —
// the panel must never fetch /users for such a caller, and falls back to
// the audit event's own actorName (never the raw actor id, which is never
// shown when a name is available).
it('falls back to actorName for a caller without users:read, and never fetches /users', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'auditor', orgId: org.id }]))),
    http.get(url('/orgs/:orgId/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/audit'), () => HttpResponse.json({ items: [makeAuditEvent({ id: 4, actorId: 'u-9', actorName: 'Someone' })], nextCursor: null })),
    http.get(url('/users'), () => {
      throw new Error('an auditor without users:read must never fetch /users');
    }),
  );
  const { user } = renderRoute('/o/acme/overview');
  const region = await openActivity(user);
  expect(await within(region).findByText('Someone')).toBeInTheDocument();
  expect(within(region).queryByText('u-9')).not.toBeInTheDocument();
});

// Fix round 2 (Important #2): with no actorName either (a blank string, as
// the API sends for some system actions), the actor type is the last
// resort — still never the raw id.
it('falls back to actorType when actorName is blank too', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'auditor', orgId: org.id }]))),
    http.get(url('/orgs/:orgId/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/audit'), () =>
      HttpResponse.json({ items: [makeAuditEvent({ id: 4, actorId: 'u-9', actorName: '', actorType: 'system' })], nextCursor: null }),
    ),
  );
  const { user } = renderRoute('/o/acme/overview');
  const region = await openActivity(user);
  expect(await within(region).findByText('system')).toBeInTheDocument();
  expect(within(region).queryByText('u-9')).not.toBeInTheDocument();
});

// Fix round 1 (review #2b): under All orgs the panel still renders (a
// global binding satisfies canAnywhere) and links land on /o/all/audit.
it('shows and links into /o/all/audit under All orgs', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'admin', orgId: null }], [org, org2]))),
    http.get(url('/certificates'), () => HttpResponse.json({ items: [makeCert({ orgId: org.id })], nextCursor: null })),
    http.get(url('/audit'), () => HttpResponse.json({ items: [makeAuditEvent({ id: 5, action: 'org.create' })], nextCursor: null })),
  );
  const { user } = renderRoute('/o/all/overview');
  const region = await openActivity(user);
  expect(await within(region).findByRole('link', { name: 'org.create' })).toHaveAttribute('href', '/o/all/audit?event=5');
});

// Fix round 1 (review #1): the query result object only changes reference
// when `dataUpdatedAt` moves, even for an identical-data poll — relTime
// must key off that, not `Date.now()`, or the label goes stale between
// polls. Fakes the clock, advances it, then triggers the same refetch a
// poll would (the 30 s interval itself is Task 9's `recentActivityQuery`
// concern, already covered there); this isolates "does the label move
// when the query re-resolves with unchanged data".
it('refreshes relative times on each poll, not just on new data', async () => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/:orgId/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/audit'), () => HttpResponse.json({ items: [makeAuditEvent({ id: 1, ts: iso(0) })], nextCursor: null })),
  );
  const { queryClient, user } = renderRoute('/o/acme/overview');
  const region = await openActivity(user);
  expect(await within(region).findByText('just now')).toBeInTheDocument();

  vi.setSystemTime(NOW + 60_100);
  await act(async () => {
    await queryClient.refetchQueries({ queryKey: ['audit', { orgId: org.id, limit: 20 }] });
  });
  await waitFor(() => expect(within(region).getByText('1 min ago')).toBeInTheDocument());
});
