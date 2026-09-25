import { http, HttpResponse } from 'msw';
import { screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeAuditEvent, makeCert, meWith, org, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

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
  renderRoute('/o/acme/overview');
  const region = await screen.findByRole('region', { name: 'Recent activity' });
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
  expect(screen.queryByRole('region', { name: 'Recent activity' })).not.toBeInTheDocument();
});
