import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Me } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, ca, iso, makeAttempt, makeCert, me, providers, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

const cert = makeCert();
const older = { id: 'v-0', serial: '03aa77', notBefore: iso(-120), notAfter: iso(-30), sha256Fingerprint: 'cd'.repeat(32), source: 'issued' };
let downloadQuery: URLSearchParams | undefined;
let renewed = false;

function base(user: Me = me) {
  return [
    // First match wins within one server.use call, so this /auth/me overrides the one in authHandlers.
    http.get(url('/auth/me'), () => HttpResponse.json(user)),
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(cert)),
    http.get(url('/orgs/org-1/certificates/c-1/versions'), () => HttpResponse.json([cert.currentVersion, older])),
    http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => HttpResponse.json([makeAttempt({ outcome: 'success', acmeErrorType: undefined })])),
    http.get(url('/orgs/org-1/certificates/c-1/manual-dns'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/certificates/c-1/versions/:vid/download'), ({ request }) => {
      downloadQuery = new URL(request.url).searchParams;
      return new HttpResponse('PK', { headers: { 'Content-Type': 'application/zip', 'Content-Disposition': 'attachment; filename="www.zip"' } });
    }),
    http.post(url('/orgs/org-1/certificates/c-1/renew'), () => ((renewed = true), new HttpResponse(null, { status: 202 }))),
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [cert], nextCursor: null })),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json([{ id: 'd-1', name: 'Cloudflare prod', providerCode: 'cloudflare', config: {} }])),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: providers, deployTargets: [], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json({})),
    http.get(url('/orgs/org-1/issuance-defaults'), () => HttpResponse.json({})),
    http.get(url('/settings/issuance_defaults'), () => HttpResponse.json({ schema: {}, value: {} })),
  ];
}

beforeEach(() => {
  downloadQuery = undefined;
  renewed = false;
  URL.createObjectURL = vi.fn(() => 'blob:test');
  URL.revokeObjectURL = vi.fn();
});

it('shows the header with a large validity bar and renews into the Attempts tab', async () => {
  server.use(...base());
  const { router, user } = renderRoute('/o/acme/certificates/c-1/overview');
  expect(await screen.findByRole('heading', { level: 1, name: 'www' })).toBeInTheDocument();
  expect(screen.getByRole('img', { name: /^Valid .* renews in 30 d$/ })).toBeInTheDocument();
  expect(screen.getByText('renews in 30 d')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Renew now' }));
  await waitFor(() => expect(renewed).toBe(true));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-1/attempts'));
  expect(await screen.findByText('Succeeded')).toBeInTheDocument();
});

it('downloads chosen PEM parts as a zip; the key needs keys:export', async () => {
  server.use(...base({ ...me, roles: ['operator'] }));
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  const { user } = renderRoute('/o/acme/certificates/c-1/overview');
  await user.click(await screen.findByRole('button', { name: 'Download' }));
  const sheet = await screen.findByRole('dialog', { name: 'Download' });
  expect(within(sheet).getByRole('button', { name: 'key' })).toBeDisabled();
  expect(within(sheet).getByRole('button', { name: 'combined' })).toBeDisabled();
  expect(within(sheet).getByRole('radio', { name: 'DER' })).toBeDisabled();
  await user.click(within(sheet).getByRole('button', { name: 'cert' }));
  await user.click(within(sheet).getByRole('button', { name: 'Download ZIP' }));
  await waitFor(() => expect(downloadQuery?.get('parts')).toBe('fullchain,cert'));
  expect(downloadQuery?.get('format')).toBe('pem');
  await waitFor(() => expect(click).toHaveBeenCalled());
  expect((click.mock.contexts[0] as HTMLAnchorElement).download).toBe('www.zip');
});

it('lists versions newest first with the current one marked', async () => {
  server.use(...base());
  renderRoute('/o/acme/certificates/c-1/versions');
  const table = await screen.findByRole('table', { name: 'Versions' });
  // The table itself renders before its own (separately-fetched) versions
  // arrive; wait for a row's content, not just the table shell.
  await within(table).findByText('04ab19f2');
  const rows = within(table).getAllByRole('row').slice(1);
  expect(rows[0]).toHaveTextContent('04ab19f2');
  expect(rows[0]).toHaveTextContent('Current');
  expect(rows[1]).toHaveTextContent('03aa77');
  expect(within(rows[1]!).getByRole('button', { name: 'Copy SHA-256 fingerprint' })).toBeInTheDocument();
});

// Controller ruling: Settings shows the certificate's configuration read-only
// (wizard-shaped sections) and links to the existing edit-wizard route
// instead of re-implementing an editable form with its own PUT flow.
it('links the Settings tab to the edit route', async () => {
  server.use(...base());
  renderRoute('/o/acme/certificates/c-1/settings');
  const link = await screen.findByRole('link', { name: 'Edit' });
  expect(link).toHaveAttribute('href', '/o/acme/certificates/c-1/edit');
});

it('sends an unknown tab to overview', async () => {
  server.use(...base());
  const { router } = renderRoute('/o/acme/certificates/c-1/bogus');
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-1/overview'));
});

it('deletes the certificate: type the name, DELETE fires, then navigates to the list', async () => {
  let deleted = false;
  server.use(http.delete(url('/orgs/org-1/certificates/c-1'), () => ((deleted = true), new HttpResponse(null, { status: 204 }))), ...base());
  const { router, user } = renderRoute('/o/acme/certificates/c-1/overview');
  await user.click(await screen.findByRole('button', { name: 'More actions' }));
  await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
  const dialog = await screen.findByRole('dialog', { name: 'Delete certificate' });
  await user.type(within(dialog).getByRole('textbox'), cert.name);
  await user.click(within(dialog).getByRole('button', { name: 'Delete certificate' }));
  await waitFor(() => expect(deleted).toBe(true));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates'));
});

// Fix round 1 (review, Take now #6): matches how AttemptsTab.test.tsx proves
// its own 2s/30s polling, one level up — the *certificate* query, not just
// attempts, must speed up while an attempt is running. Uses real timers
// (only `Date` is faked, by the global `beforeEach` in test/setup.ts): the
// route's own lazy-loaded chunk and TanStack Router's navigation both
// resolve through real microtask/timer chains that fake `setTimeout`
// disrupts, unlike AttemptsTab.test.tsx's plain `renderUI` with no router.
it(
  'polls the certificate every 2 s while an attempt is running',
  async () => {
    let calls = 0;
    server.use(
      http.get(url('/orgs/org-1/certificates/c-1'), () => ((calls++), HttpResponse.json(cert))),
      http.get(url('/orgs/org-1/certificates/c-1/attempts'), () =>
        HttpResponse.json([makeAttempt({ outcome: 'running', finishedAt: undefined, acmeErrorType: undefined, retryAfter: undefined })]),
      ),
      ...base(),
    );
    renderRoute('/o/acme/certificates/c-1/overview');
    await screen.findByRole('heading', { level: 1, name: 'www' });
    const first = calls;
    await waitFor(() => expect(calls).toBeGreaterThan(first), { timeout: 3_000 });
  },
  10_000,
);
