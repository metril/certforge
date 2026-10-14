import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeAuditEvent, makeGrant, makeTarget, meWith, traefikSchema, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

beforeEach(() => {
  vi.stubGlobal('matchMedia', (query: string) => ({ matches: query === '(min-width: 768px)', media: query, addEventListener: () => {}, removeEventListener: () => {} }));
});
afterEach(() => vi.unstubAllGlobals());

function events() {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'admin', orgId: null }]))),
    http.get(url('/audit'), () =>
      HttpResponse.json({
        items: [
          makeAuditEvent({ id: 3, action: 'grant.update', resourceType: 'grant', resourceId: 'g-9' }),
          makeAuditEvent({ id: 2, action: 'settings.update', resourceType: 'settings', resourceId: 'general', orgId: null }),
          makeAuditEvent({ id: 1, action: 'certificate.renew', resourceType: 'certificate', resourceId: 'c-1' }),
        ],
        nextCursor: null,
      }),
    ),
  );
}

it('links the resource and the actor, and leaves a resource without a page as text', async () => {
  events();
  renderRoute('/o/acme/audit');
  await screen.findByText('certificate.renew');
  expect(screen.getByRole('link', { name: 'c-1' })).toHaveAttribute('href', '/o/acme/certificates/c-1/overview');
  expect(screen.getAllByRole('link', { name: 'admin' })[0]).toHaveAttribute('href', '/settings/access?tab=users');
  expect(screen.getByText('general')).toBeInTheDocument();
  expect(screen.queryByRole('link', { name: 'general' })).toBeNull();
});

it('resolves a grant on click and opens it on its target', async () => {
  events();
  let query = '';
  server.use(
    http.get(url('/orgs/org-1/deploy-targets/t-4'), () => HttpResponse.json(makeTarget({ id: 't-4', runsOn: 'server' }))),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [makeTarget({ id: 't-4', runsOn: 'server' })] })),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema], deployCredentials: [], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/grants'), ({ request }) => {
      query = new URL(request.url).search;
      return HttpResponse.json({ items: [makeGrant({ id: 'g-9', runsOn: 'server', clientId: null, deployTargetId: 't-4' })] });
    }),
  );
  const { user, router } = renderRoute('/o/acme/audit');
  const row = (await screen.findByText('grant.update')).closest('tr')!;
  await user.click(within(row).getByRole('button', { name: 'g-9' }));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/delivery/targets/t-4/grants'));
  expect(new URLSearchParams(query).get('grantId')).toBe('g-9');
  expect(router.state.location.search).toEqual({ open: 'g-9' });
});
