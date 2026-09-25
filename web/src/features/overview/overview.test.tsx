import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, iso, makeCert, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let ready = true;
let renewed: string[] = [];
beforeEach(() => {
  ready = true;
  renewed = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get('*/readyz', () =>
      ready
        ? HttpResponse.json({ status: 'ready', checks: { database: 'ok', kek: 'ok' } })
        : HttpResponse.json({ status: 'unavailable', checks: { database: 'ok', kek: 'failed' } }, { status: 503 }),
    ),
    http.get(url('/orgs/org-1/certificates'), () =>
      HttpResponse.json({
        items: [
          makeCert({ id: 'c-1', name: 'www', nextRenewAt: iso(3) }),
          makeCert({ id: 'c-2', name: 'api', status: 'failed', failureCount: 2, lastError: 'dns: NXDOMAIN' }),
          makeCert({ id: 'c-3', name: 'lab', status: 'pending', currentVersion: undefined, verificationRules: [{ match: 'lab.local', method: 'manual-dns' }] }),
        ],
        nextCursor: null,
      }),
    ),
    http.get(url('/orgs/org-1/certificates/c-3/manual-dns'), () => HttpResponse.json([{ name: '_acme-challenge.lab.local', type: 'TXT', value: 'abc', ttl: 60 }])),
    http.post(url('/orgs/org-1/certificates/:id/renew'), ({ params }) => (renewed.push(params.id as string), new HttpResponse(null, { status: 202 }))),
  );
});

it('pins manual-dns cards, lists attention items with an inline fix, and links count tiles to filters', async () => {
  const { user } = renderRoute('/o/acme/overview');
  expect(await screen.findByRole('region', { name: 'Manual DNS for lab' })).toBeInTheDocument();
  const queue = screen.getByRole('region', { name: 'Needs attention' });
  const row = within(queue).getByText('api').closest('li')!;
  expect(row).toHaveTextContent('dns: NXDOMAIN');
  await user.click(within(row).getByRole('button', { name: 'Renew now' }));
  await waitFor(() => expect(renewed).toEqual(['c-2']));
  expect(screen.getByRole('link', { name: /1 Failed/ })).toHaveAttribute('href', '/o/acme/certificates?status=failed');
  const upcoming = screen.getByRole('region', { name: 'Upcoming renewals' });
  expect(within(upcoming).getByText('www')).toBeInTheDocument();
  expect(screen.queryByRole('alert', { name: /Server not ready/ })).toBeNull();
});

it('shows the health strip only when the server is not ready', async () => {
  ready = false;
  renderRoute('/o/acme/overview');
  expect(await screen.findByText('Server not ready')).toBeInTheDocument();
  expect(screen.getByText('kek: failed')).toBeInTheDocument();
});
