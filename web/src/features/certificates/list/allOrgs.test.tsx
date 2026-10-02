import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { makeCert, meWith, org, org2, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// Desktop viewport (list.test.tsx's convention): table rows and full nav
// labels, not the below-md card layout / icon-rail sidebar.
beforeEach(() => {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)' || query === '(min-width: 1280px)',
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
});

function as(bindings: Parameters<typeof meWith>[0]) {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith(bindings, [org, org2]))),
    http.get(url('/certificates'), () =>
      HttpResponse.json({ items: [makeCert({ id: 'c-1', orgId: org.id }), makeCert({ id: 'c-2', name: 'db', orgId: org2.id })], nextCursor: null })),
  );
}

it('lists certificates across orgs, read-only', async () => {
  as([{ role: 'admin', orgId: null }]);
  renderRoute('/o/all/certificates');
  const table = await screen.findByRole('table', { name: 'Certificates' });
  expect(within(table).getByText(/Lab/)).toBeInTheDocument();
  expect(within(table).getByRole('link', { name: 'db' })).toHaveAttribute('href', '/o/lab/certificates/c-2/overview');
  expect(screen.getByRole('status', { name: 'Read-only view' })).toHaveTextContent('All orgs');
  expect(screen.queryByRole('link', { name: 'New certificate' })).not.toBeInTheDocument();
});

it('hides writes on the All orgs overview even for admins', async () => {
  as([{ role: 'admin', orgId: null }]);
  server.use(http.get(url('/certificates'), () =>
    HttpResponse.json({ items: [makeCert({ id: 'c-9', name: 'broken', status: 'failed', failureCount: 2, lastError: 'boom', orgId: org2.id })], nextCursor: null })));
  renderRoute('/o/all/overview');
  const queue = await screen.findByRole('region', { name: 'Needs attention' });
  expect(await within(queue).findByRole('link', { name: 'broken' })).toHaveAttribute('href', '/o/lab/certificates/c-9/attempts');
  expect(screen.queryByRole('button', { name: 'Renew now' })).not.toBeInTheDocument();
});

it.each([
  '/o/all/certificates/new',
  '/o/all/issuers/cas',
  '/o/all/certificates/c-1',
  '/o/all/certificates/c-1/overview',
  '/o/all/certificates/c-1/edit',
])('sends %s to the All orgs overview', async (path) => {
  as([{ role: 'admin', orgId: null }]);
  const { router } = renderRoute(path);
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/all/overview'));
});

it('is not found without a global binding', async () => {
  as([{ role: 'org-admin', orgId: org.id }]);
  renderRoute('/o/all/overview');
  expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
});

it('disables Issuers in the sidebar', async () => {
  as([{ role: 'admin', orgId: null }]);
  renderRoute('/o/all/overview');
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  expect(within(nav).getByText('Issuers').closest('[aria-disabled="true"]')).not.toBeNull();
});

it('hides Import under All orgs', async () => {
  as([{ role: 'admin', orgId: null }]);
  renderRoute('/o/all/certificates');
  await screen.findByRole('table', { name: 'Certificates' });
  expect(screen.queryByRole('button', { name: 'Import' })).not.toBeInTheDocument();
});

it('shows the org name on card rows below md', async () => {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
  as([{ role: 'admin', orgId: null }]);
  renderRoute('/o/all/certificates');
  const link = await screen.findByRole('link', { name: /^db/ });
  expect(within(link).getByText(/Lab/)).toBeInTheDocument();
});
