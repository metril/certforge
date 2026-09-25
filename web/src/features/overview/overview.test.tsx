import { http, HttpResponse } from 'msw';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, iso, makeCert, meWith, problem, url } from '@/test/fixtures';
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
          // Controller ruling: a certificate already `active` (not just a
          // first-issuance `pending` one) still gets a mounted ManualDnsCard
          // while it's renewing over manual-dns and waiting for TXT records.
          makeCert({ id: 'c-4', name: 'proxy', status: 'active', verificationRules: [{ match: 'proxy.example.com', method: 'manual-dns' }] }),
        ],
        nextCursor: null,
      }),
    ),
    http.get(url('/orgs/org-1/certificates/c-3/manual-dns'), () => HttpResponse.json([{ name: '_acme-challenge.lab.local', type: 'TXT', value: 'abc', ttl: 60 }])),
    http.get(url('/orgs/org-1/certificates/c-4/manual-dns'), () => HttpResponse.json([{ name: '_acme-challenge.proxy.example.com', type: 'TXT', value: 'xyz', ttl: 60 }])),
    http.post(url('/orgs/org-1/certificates/:id/renew'), ({ params }) => (renewed.push(params.id as string), new HttpResponse(null, { status: 202 }))),
  );
});

it('pins manual-dns cards (including a renewing active certificate), lists attention items with an inline fix, and links count tiles to filters', async () => {
  const { user } = renderRoute('/o/acme/overview');
  expect(await screen.findByRole('region', { name: 'Manual DNS for lab' })).toBeInTheDocument();
  expect(await screen.findByRole('region', { name: 'Manual DNS for proxy' })).toBeInTheDocument();
  const queue = screen.getByRole('region', { name: 'Needs attention' });
  const row = within(queue).getByText('api').closest('li')!;
  expect(row).toHaveTextContent('dns: NXDOMAIN');
  await user.click(within(row).getByRole('button', { name: 'Renew now' }));
  await waitFor(() => expect(renewed).toEqual(['c-2']));
  expect(await screen.findByText('Renewal queued for api')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: /1 Failed/ })).toHaveAttribute('href', '/o/acme/certificates?status=failed');
  const upcoming = screen.getByRole('region', { name: 'Upcoming renewals' });
  expect(within(upcoming).getByText('www')).toBeInTheDocument();
  expect(screen.queryByRole('alert', { name: /Server not ready/ })).toBeNull();
});

it('shows a failure toast naming the certificate when Renew now fails', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/c-2/renew'), () => problem(500, 'boom')));
  const { user } = renderRoute('/o/acme/overview');
  const queue = await screen.findByRole('region', { name: 'Needs attention' });
  // `findByText` (not `getByText`): the section's own aria-label already
  // exists during the certificates query's brief pending render (all-zero
  // counts, "Nothing needs attention"), before the real fixture data
  // lands — this has to keep polling past that transient frame.
  const row = (await within(queue).findByText('api')).closest('li')!;
  await user.click(within(row).getByRole('button', { name: 'Renew now' }));
  expect(await screen.findByText('Renewal failed for api.')).toBeInTheDocument();
});

it('shows the health strip only when the server is not ready', async () => {
  ready = false;
  renderRoute('/o/acme/overview');
  expect(await screen.findByText('Server not ready')).toBeInTheDocument();
  expect(screen.getByText('kek: failed')).toBeInTheDocument();
});

it('shows Retry when the certificates fetch fails', async () => {
  server.use(http.get(url('/orgs/org-1/certificates'), () => problem(500, 'boom')));
  renderRoute('/o/acme/overview');
  expect(await screen.findByRole('button', { name: 'Retry' })).toBeInTheDocument();
  expect(screen.getByText(/boom/)).toBeInTheDocument();
});

it('keeps the brushed expiry range in the URL, and clears it there too', async () => {
  const rect = { left: 0, top: 0, right: 1000, bottom: 56, width: 1000, height: 56, x: 0, y: 0, toJSON: () => undefined } as DOMRect;
  const { router, user } = renderRoute('/o/acme/overview');
  const svg = await screen.findByRole('img', { name: /certificates expire in the next 90 days/ });
  const spy = vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue(rect);
  try {
    // x=100 -> 9 d, x=500 -> 45 d (round(x / 1000 * 90)).
    fireEvent.pointerDown(svg, { clientX: 100 });
    fireEvent.pointerMove(svg, { clientX: 500 });
    fireEvent.pointerUp(svg, { clientX: 500 });
  } finally {
    spy.mockRestore();
  }
  await waitFor(() => expect(router.state.location.search).toEqual({ range: [9, 45] }));
  expect(await screen.findByText('Expiring in 9 to 45 days')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Clear range' }));
  await waitFor(() => expect(router.state.location.search).toEqual({}));
  expect(screen.queryByText(/^Expiring in /)).toBeNull();
});

// Fix round 2 (Important #1): a viewer lacks certs:write, so the empty
// state's New certificate button must stay visible but disabled.
it('disables New certificate in the empty state for a viewer', async () => {
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: 'org-1' }]))),
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [], nextCursor: null })),
  );
  renderRoute('/o/acme/overview');
  expect(await screen.findByRole('button', { name: 'New certificate' })).toBeDisabled();
});
