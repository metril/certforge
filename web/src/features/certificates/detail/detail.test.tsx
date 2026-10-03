import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Me } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, ca, iso, makeAttempt, makeCert, me, meWith, org, problem, providers, url } from '@/test/fixtures';
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
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json({ builtin: {} })),
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

// I2 (Important): the header's Renew now used `renew.mutate([cert.id])` with
// no options at all — `useRenewCertificates` is `meta: { silent: true }`
// (Task 11: bulk renew shows its own toast), so a failure here previously
// surfaced nowhere on the page.
it('shows a toast when Renew now fails', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/c-1/renew'), () => problem(500, 'boom')), ...base());
  const { user } = renderRoute('/o/acme/certificates/c-1/overview');
  await user.click(await screen.findByRole('button', { name: 'Renew now' }));
  expect(await screen.findByText('Renewal failed for www.')).toBeInTheDocument();
});

// I1 (Important): a certificate can be `pending` (its very first issuance
// just queued) before the worker has created an attempt row at all — a
// fetch with `outcome: 'running'` doesn't exist yet, so `running` alone
// missed this window and the page polled at the 30s list pace instead of 2s.
it(
  'polls the certificate every 2 s while its own status is pending, even with no running attempt yet',
  async () => {
    let calls = 0;
    server.use(
      http.get(url('/orgs/org-1/certificates/c-1'), () => ((calls++), HttpResponse.json(makeCert({ status: 'pending' })))),
      http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => HttpResponse.json([])),
      ...base(),
    );
    renderRoute('/o/acme/certificates/c-1/overview');
    await screen.findByRole('heading', { level: 1, name: 'www' });
    const first = calls;
    await waitFor(() => expect(calls).toBeGreaterThan(first), { timeout: 3_000 });
  },
  10_000,
);

// I1: a renew queued from a tab's own empty-state button (no attempt exists
// yet to flip `running`, and this certificate's own `status` is already
// `active` from a previous issuance, so neither of the other two live
// conditions apply) must still start the 2s pace immediately, via the
// `liveUntil` window `renewNow` sets — not wait for the 30s list pace to
// happen to notice the new attempt. Landing straight on the Versions tab
// (not Attempts) also rules out "arriving on the attempts tab already
// starts the window" as an alternate explanation.
it(
  "polls every 2 s for a while after Renew now from the Versions tab's empty state",
  async () => {
    let calls = 0;
    server.use(
      http.get(url('/orgs/org-1/certificates/c-1'), () => ((calls++), HttpResponse.json(cert))),
      http.get(url('/orgs/org-1/certificates/c-1/versions'), () => HttpResponse.json([])),
      ...base(),
    );
    const { user } = renderRoute('/o/acme/certificates/c-1/versions');
    // Re-review fix: the header's own "Renew now" button is *always*
    // rendered too (CertificateHeader, above the tabs) — an unscoped
    // `findByRole('button', { name: 'Renew now' })` resolves to it as soon
    // as it mounts, before the Versions tab's own empty-state fetch even
    // settles enough to render its own same-named button, so this test used
    // to click the header's button instead. Scoping to the visible tabpanel
    // (only the active tab's content matches `getByRole`'s default
    // hidden-elements-excluded behaviour) guarantees this exercises the
    // Versions tab's own `onRenew` wiring, not the header's.
    const panel = await screen.findByRole('tabpanel');
    await user.click(await within(panel).findByRole('button', { name: 'Renew now' }));
    await waitFor(() => expect(renewed).toBe(true));
    // `useRenewCertificates`'s own onSuccess invalidates the certificate
    // query, triggering one incidental refetch of its own; capturing the
    // `calls` baseline before that settles would let a bare "calls
    // increased" assertion below pass on that one incidental call alone,
    // even without the liveUntil fix. Let it land first, then baseline.
    await waitFor(() => expect(calls).toBeGreaterThan(0));
    await new Promise((r) => setTimeout(r, 300));
    const first = calls;
    await waitFor(() => expect(calls).toBeGreaterThan(first), { timeout: 3_000 });
  },
  10_000,
);

it('downloads chosen PEM parts as a zip; the key needs keys:export', async () => {
  server.use(...base({ ...me, roles: ['operator'], bindings: [{ role: 'operator', orgId: org.id }] }));
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  const { user } = renderRoute('/o/acme/certificates/c-1/overview');
  await user.click(await screen.findByRole('button', { name: 'Download' }));
  const sheet = await screen.findByRole('dialog', { name: 'Download' });
  expect(within(sheet).getByRole('button', { name: 'key' })).toBeDisabled();
  expect(within(sheet).getByRole('button', { name: 'combined' })).toBeDisabled();
  expect(within(sheet).getByRole('radio', { name: 'DER' })).toBeEnabled();
  await user.click(within(sheet).getByRole('button', { name: 'cert' }));
  await user.click(within(sheet).getByRole('button', { name: 'Download ZIP' }));
  await waitFor(() => expect(downloadQuery?.get('parts')).toBe('fullchain,cert'));
  expect(downloadQuery?.get('format')).toBe('pem');
  await waitFor(() => expect(click).toHaveBeenCalled());
  expect((click.mock.contexts[0] as HTMLAnchorElement).download).toBe('www.zip');
});

// Fix round 1 (review, Important #2): a viewer only has read actions in its
// own org — no certs:issue, certs:write, or keys:export — so Renew now and
// Delete stay visible but disabled (tooltip-gated, same as the key/combined
// download parts), never enabled.
it('a viewer with an org binding sees neither Renew nor Delete enabled and the key chips are disabled', async () => {
  server.use(...base({ ...me, roles: ['viewer'], bindings: [{ role: 'viewer', orgId: org.id }] }));
  const { user } = renderRoute('/o/acme/certificates/c-1/overview');
  expect(await screen.findByRole('button', { name: 'Renew now' })).toBeDisabled();
  await user.click(await screen.findByRole('button', { name: 'More actions' }));
  expect(await screen.findByRole('menuitem', { name: 'Delete' })).toHaveAttribute('data-disabled');
  await user.keyboard('{Escape}');
  await user.click(await screen.findByRole('button', { name: 'Download' }));
  const sheet = await screen.findByRole('dialog', { name: 'Download' });
  expect(within(sheet).getByRole('button', { name: 'key' })).toBeDisabled();
  expect(within(sheet).getByRole('button', { name: 'combined' })).toBeDisabled();
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

// Fix round 2 (Important #1): a viewer has certs:read but not certs:write —
// the Settings tab's Edit link becomes a disabled button instead.
it('disables the Settings tab Edit link for a viewer', async () => {
  server.use(...base(meWith([{ role: 'viewer', orgId: org.id }])));
  renderRoute('/o/acme/certificates/c-1/settings');
  expect(await screen.findByRole('button', { name: 'Edit' })).toBeDisabled();
  expect(screen.queryByRole('link', { name: 'Edit' })).not.toBeInTheDocument();
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

// A renewal landing moves the certificate to a new current version; the
// versions list (and anything keyed under it) must refetch, not wait for a
// manual reload.
it(
  'refetches the versions list when the current version changes',
  async () => {
    let certCalls = 0;
    let versionCalls = 0;
    const renewedCert = makeCert({ currentVersion: { ...cert.currentVersion!, id: 'v-new' } });
    server.use(
      http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(++certCalls === 1 ? cert : renewedCert)),
      http.get(url('/orgs/org-1/certificates/c-1/versions'), () => ((versionCalls++), HttpResponse.json([cert.currentVersion, older]))),
      http.get(url('/orgs/org-1/certificates/c-1/attempts'), () =>
        HttpResponse.json([makeAttempt({ outcome: 'running', finishedAt: undefined, acmeErrorType: undefined, retryAfter: undefined })]),
      ),
      ...base(),
    );
    renderRoute('/o/acme/certificates/c-1/versions');
    await screen.findByRole('heading', { level: 1, name: 'www' });
    // One load when the tab mounts, a second once the renewal shows up.
    await waitFor(() => expect(certCalls).toBeGreaterThan(1), { timeout: 4_000 });
    await waitFor(() => expect(versionCalls).toBeGreaterThan(1), { timeout: 4_000 });
  },
  10_000,
);
