import { delay, http, HttpResponse } from 'msw';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, iso, makeCert, makeClient, makeMonitor, meWith, NOW, org, org2, problem, url } from '@/test/fixtures';
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
          makeCert({ id: 'c-3', name: 'lab', status: 'pending', currentVersion: undefined, verificationRules: [{ match: 'lab.local', method: 'manual-dns', via: 'server' }] }),
          // Controller ruling: a certificate already `active` (not just a
          // first-issuance `pending` one) still gets a mounted ManualDnsCard
          // while it's renewing over manual-dns and waiting for TXT records.
          makeCert({ id: 'c-4', name: 'proxy', status: 'active', verificationRules: [{ match: 'proxy.example.com', method: 'manual-dns', via: 'server' }] }),
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

it('queues client problems with one fix each', async () => {
  server.use(
    http.get(url('/orgs/org-1/clients'), () =>
      HttpResponse.json({
        items: [
          makeClient({ id: 'cl-1', name: 'web-1', driftCount: 1 }),
          makeClient({ id: 'cl-2', name: 'db-1', connected: false, online: false, lastSeen: iso(-1) }),
          makeClient({ id: 'cl-3', name: 'edge-1', agentCertNotAfter: iso(5) }),
          makeClient({ id: 'cl-4', name: 'cron-1', connected: false, online: true, lastSeen: new Date(NOW - 30_000).toISOString() }),
          makeClient({ id: 'cl-5', name: 'api-1', failedCount: 1 }),
        ],
        nextCursor: null,
      }),
    ),
  );
  renderRoute('/o/acme/overview');
  const queue = await screen.findByRole('region', { name: 'Needs attention' });
  const drift = (await within(queue).findByRole('link', { name: 'web-1' })).closest('li')!;
  expect(drift).toHaveTextContent('Drift');
  expect(within(drift).getByRole('link', { name: 'Review' })).toHaveAttribute('href', '/o/acme/clients/cl-1/certificates');
  const offline = within(queue).getByRole('link', { name: 'db-1' }).closest('li')!;
  expect(offline).toHaveTextContent('Last seen 1 d ago');
  expect(within(offline).getByRole('link', { name: 'Open' })).toHaveAttribute('href', '/o/acme/clients/cl-2/certificates');
  const cert = within(queue).getByRole('link', { name: 'edge-1' }).closest('li')!;
  expect(within(cert).getByRole('link', { name: 'Re-enrol' })).toHaveAttribute('href', '/o/acme/clients/cl-3/settings');
  const deployFailed = within(queue).getByRole('link', { name: 'api-1' }).closest('li')!;
  expect(deployFailed).toHaveTextContent('Deploy failed');
  expect(within(deployFailed).getByRole('link', { name: 'Review' })).toHaveAttribute('href', '/o/acme/clients/cl-5/certificates');
  // A pull client seen 30 s ago is online, so it is not queued as offline.
  expect(within(queue).queryByRole('link', { name: 'cron-1' })).not.toBeInTheDocument();
});

it('gives a client problem no fix link when the caller lacks clients:write', async () => {
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: 'org-1' }]))),
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/orgs/org-1/clients'), () => HttpResponse.json({ items: [makeClient({ id: 'cl-1', name: 'web-1', driftCount: 1 })], nextCursor: null })),
  );
  renderRoute('/o/acme/overview');
  const queue = await screen.findByRole('region', { name: 'Needs attention' });
  const row = (await within(queue).findByRole('link', { name: 'web-1' })).closest('li')!;
  expect(row).toHaveTextContent('Drift');
  expect(within(row).queryByRole('link', { name: 'Review' })).not.toBeInTheDocument();
});

it('under All orgs, gates each client problem\'s fix link by that client\'s own org', async () => {
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: 'org-1' }, { role: 'viewer', orgId: 'org-2' }, { role: 'viewer', orgId: null }], [org, org2]))),
    http.get(url('/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/clients'), () =>
      HttpResponse.json({
        items: [
          makeClient({ id: 'cl-1', orgId: 'org-1', name: 'web-1', driftCount: 1 }),
          makeClient({ id: 'cl-2', orgId: 'org-2', name: 'lab-1', driftCount: 1 }),
        ],
        nextCursor: null,
      }),
    ),
  );
  renderRoute('/o/all/overview');
  const queue = await screen.findByRole('region', { name: 'Needs attention' });
  const writable = (await within(queue).findByRole('link', { name: 'web-1' })).closest('li')!;
  expect(within(writable).getByRole('link', { name: 'Review' })).toHaveAttribute('href', '/o/acme/clients/cl-1/certificates');
  const readOnly = within(queue).getByRole('link', { name: 'lab-1' }).closest('li')!;
  expect(within(readOnly).queryByRole('link', { name: 'Review' })).not.toBeInTheDocument();
});

it('warns when the clients walk was truncated', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/orgs/org-1/clients'), () => HttpResponse.json({ items: [makeClient()], nextCursor: 'next' })),
  );
  renderRoute('/o/acme/overview');
  const queue = await screen.findByRole('region', { name: 'Needs attention' });
  expect(await within(queue).findByText('Client checks cover the first 50 clients only.')).toBeInTheDocument();
});

it('shows a Retry line instead of "Nothing needs attention" when the clients check fails', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/orgs/org-1/clients'), () => problem(500, 'boom')),
  );
  renderRoute('/o/acme/overview');
  const queue = await screen.findByRole('region', { name: 'Needs attention' });
  expect(await within(queue).findByText(/Couldn.t check clients/)).toBeInTheDocument();
  expect(within(queue).queryByText('Nothing needs attention.')).not.toBeInTheDocument();
  expect(within(queue).getByRole('button', { name: 'Retry' })).toBeInTheDocument();
});

it('warns when the agent listener certificate is close to expiry', async () => {
  server.use(http.get(url('/agents/ca'), () => HttpResponse.json({ items: [], listener: { caId: 'aca-1', names: ['cf.lan'], notAfter: iso(5) } })));
  renderRoute('/o/acme/overview');
  const strip = await screen.findByRole('alert', { name: 'Server health' });
  expect(strip).toHaveTextContent('Agent listener certificate expires in 5 d');
  expect(within(strip).getByRole('link', { name: 'Settings → Agents' })).toHaveAttribute('href', '/settings/agents');
});

it('says the agent listener certificate has expired once past its notAfter', async () => {
  server.use(http.get(url('/agents/ca'), () => HttpResponse.json({ items: [], listener: { caId: 'aca-1', names: ['cf.lan'], notAfter: iso(-2) } })));
  renderRoute('/o/acme/overview');
  const strip = await screen.findByRole('alert', { name: 'Server health' });
  expect(strip).toHaveTextContent('Agent listener certificate expired 2 d ago');
});

it('stays silent about the agent listener certificate at 14 days or more', async () => {
  server.use(http.get(url('/agents/ca'), () => HttpResponse.json({ items: [], listener: { caId: 'aca-1', names: ['cf.lan'], notAfter: iso(14) } })));
  renderRoute('/o/acme/overview');
  await screen.findByRole('link', { name: 'api' });
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('monitor row links and checks now', async () => {
  let checked: string | undefined;
  server.use(
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/orgs/org-1/monitors'), () =>
      HttpResponse.json([makeMonitor({ id: 'mon-1', name: 'edge', state: 'mismatch', lastFingerprint: 'ab'.repeat(32), expectedCertificateName: 'www.example.com' })]),
    ),
    http.post(url('/orgs/org-1/monitors/:id/check'), ({ params }) => {
      checked = params.id as string;
      return HttpResponse.json(makeMonitor({ id: 'mon-1', name: 'edge', state: 'ok' }));
    }),
  );
  const { user } = renderRoute('/o/acme/overview');
  const queue = await screen.findByRole('region', { name: 'Needs attention' });
  const row = (await within(queue).findByRole('link', { name: 'edge' })).closest('li')!;
  expect(within(row).getByRole('link', { name: 'edge' })).toHaveAttribute('href', '/o/acme/alerts/monitors?edit=mon-1');
  expect(row).toHaveTextContent('edge.example.com:443');
  expect(row).toHaveTextContent(`Serving ${'ab'.repeat(8)}…; expected www.example.com`);
  await user.click(within(row).getByRole('button', { name: 'Check now' }));
  await waitFor(() => expect(checked).toBe('mon-1'));
});

it('no monitor query without alerts:read', async () => {
  let requested = false;
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: 'org-2' }], [org, org2]))),
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/orgs/org-1/monitors'), () => {
      requested = true;
      return HttpResponse.json([]);
    }),
  );
  renderRoute('/o/acme/overview');
  await screen.findByText('Nothing needs attention.');
  expect(requested).toBe(false);
});

it('no monitor query in all orgs', async () => {
  let requested = false;
  server.use(
    http.get(url('/auth/me'), () =>
      HttpResponse.json(meWith([{ role: 'org-admin', orgId: 'org-1' }, { role: 'viewer', orgId: 'org-2' }, { role: 'viewer', orgId: null }], [org, org2])),
    ),
    http.get(url('/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    // Any org, not just org-1: under All orgs, `org.id` is the literal
    // string 'all' (batch 4 review), so a missing `!allOrgs` guard would hit
    // /orgs/all/monitors — served silently by the default
    // /orgs/:orgId/monitors handler (test/server.ts) — and never the
    // literal /orgs/org-1/monitors this watched before, making the old
    // assertion pass regardless of whether the guard was there.
    http.get(url('/orgs/:orgId/monitors'), () => {
      requested = true;
      return HttpResponse.json([]);
    }),
  );
  renderRoute('/o/all/overview');
  await screen.findByText('Nothing needs attention.');
  expect(requested).toBe(false);
});


it('keeps the page and shows a stale notice when a later poll fails', async () => {
  const { queryClient } = renderRoute('/o/acme/overview');
  await screen.findByRole('region', { name: 'Needs attention' });
  await screen.findByText('api');
  server.use(http.get(url('/orgs/org-1/certificates'), () => problem(500, 'boom')));
  await queryClient.refetchQueries({ queryKey: ['certs'] });
  expect(await screen.findByRole('status')).toHaveTextContent(/showing the last loaded data/);
  expect(screen.getByText('api')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
});

it('only disables Renew now on the row being renewed', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/:id/renew'), async () => (await delay(300), new HttpResponse(null, { status: 202 }))));
  const { user } = renderRoute('/o/acme/overview');
  const queue = await screen.findByRole('region', { name: 'Needs attention' });
  const rows = (await within(queue).findAllByRole('button', { name: 'Renew now' })).length;
  expect(rows).toBeGreaterThan(0);
  const first = within(queue).getAllByRole('button', { name: 'Renew now' })[0]!;
  await user.click(first);
  await waitFor(() => expect(first).toBeDisabled());
  for (const b of within(queue).getAllByRole('button', { name: 'Renew now' }).slice(1)) expect(b).toBeEnabled();
});

it('range presets are keyboard buttons that stay in sync with the brush', async () => {
  const rect = { left: 0, top: 0, right: 1000, bottom: 56, width: 1000, height: 56, x: 0, y: 0, toJSON: () => undefined } as DOMRect;
  const { router, user } = renderRoute('/o/acme/overview');
  const svg = await screen.findByRole('img', { name: /certificates expire in the next 90 days/ });
  const p30 = screen.getByRole('button', { name: '30 d' });
  p30.focus();
  await user.keyboard('{Enter}');
  await waitFor(() => expect(router.state.location.search).toEqual({ range: [0, 30] }));
  expect(p30).toHaveAttribute('aria-pressed', 'true');
  const spy = vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue(rect);
  try {
    fireEvent.pointerDown(svg, { clientX: 100 });
    fireEvent.pointerMove(svg, { clientX: 500 });
    fireEvent.pointerUp(svg, { clientX: 500 });
  } finally {
    spy.mockRestore();
  }
  await waitFor(() => expect(router.state.location.search).toEqual({ range: [9, 45] }));
  expect(screen.getByRole('button', { name: '30 d' })).toHaveAttribute('aria-pressed', 'false');
  await user.click(screen.getByRole('button', { name: '7 d' }));
  await waitFor(() => expect(router.state.location.search).toEqual({ range: [0, 7] }));
});
