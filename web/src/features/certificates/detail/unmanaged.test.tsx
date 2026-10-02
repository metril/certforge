import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { help } from '@/lib/help';
import { server } from '@/test/server';
import { authHandlers, makeCert, makeVersion, problem, providers, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

const cert = makeCert({ managed: false, nextRenewAt: null });
let renewCalls: number;
let versionsCalls: number;
let versions: ReturnType<typeof makeVersion>[];

function base() {
  return [
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(cert)),
    http.get(url('/orgs/org-1/certificates/c-1/versions'), () => ((versionsCalls += 1), HttpResponse.json(versions))),
    http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/certificates/c-1/manual-dns'), () => HttpResponse.json([])),
    http.post(url('/orgs/org-1/certificates/c-1/renew'), () => ((renewCalls += 1), problem(409, 'managed externally'))),
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [cert], nextCursor: null })),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json([])),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: providers, deployTargets: [], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json({ builtin: {} })),
    http.get(url('/orgs/org-1/issuance-defaults'), () => HttpResponse.json({})),
    http.get(url('/settings/issuance_defaults'), () => HttpResponse.json({ schema: {}, value: {} })),
  ];
}

beforeEach(() => {
  renewCalls = 0;
  versionsCalls = 0;
  versions = [cert.currentVersion!];
  server.use(...base());
});

it('shows the Managed externally chip and disables Renew now with its own tooltip', async () => {
  const { user } = renderRoute('/o/acme/certificates/c-1/overview');
  expect(await screen.findByText('Managed externally')).toBeInTheDocument();
  const renewButton = screen.getByRole('button', { name: 'Renew now' });
  expect(renewButton).toBeDisabled();
  await user.hover(renewButton);
  expect(await screen.findByText(help['cert.renewUnmanaged'].text)).toBeInTheDocument();
  expect(screen.getByText('Not renewed here')).toBeInTheDocument();
});

it('uploads a new version from the header action, then closes and refetches versions', async () => {
  let body: unknown;
  server.use(
    http.post(url('/orgs/org-1/certificates/c-1/versions/upload'), async ({ request }) => {
      body = await request.json();
      return HttpResponse.json(makeVersion({ id: 'v-2' }), { status: 201 });
    }),
  );
  // Versions tab, so versionsQuery has an active observer: invalidateQueries
  // only refetches queries with one, and the header (with its Upload new
  // version action) renders above the tabs regardless of which is active.
  const { user } = renderRoute('/o/acme/certificates/c-1/versions');
  await screen.findByRole('table', { name: 'Versions' });
  const initialVersionsCalls = versionsCalls;
  await user.click(screen.getByRole('button', { name: 'Upload new version' }));
  const sheet = await screen.findByRole('dialog', { name: 'Upload new version' });
  await user.type(within(sheet).getByLabelText('Certificate'), 'CERT-DATA');
  await user.click(within(sheet).getByRole('button', { name: 'Upload' }));
  await waitFor(() => expect(body).toEqual({ certificatePem: 'CERT-DATA' }));
  await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Upload new version' })).not.toBeInTheDocument());
  await waitFor(() => expect(versionsCalls).toBeGreaterThan(initialVersionsCalls));
});

it('offers no Upload new version action for a managed certificate', async () => {
  server.use(http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(makeCert({ managed: true }))));
  renderRoute('/o/acme/certificates/c-1/overview');
  await screen.findByRole('heading', { level: 1, name: 'www' });
  expect(screen.queryByRole('button', { name: 'Upload new version' })).not.toBeInTheDocument();
});

it('disables Settings tab Edit for an unmanaged certificate', async () => {
  const { user } = renderRoute('/o/acme/certificates/c-1/settings');
  const editButton = await screen.findByRole('button', { name: 'Edit' });
  expect(editButton).toBeDisabled();
  expect(screen.queryByRole('link', { name: 'Edit' })).not.toBeInTheDocument();
  await user.hover(editButton);
  expect(await screen.findByText(help['cert.renewUnmanaged'].text)).toBeInTheDocument();
});

it('redirects the edit route to overview for an unmanaged certificate', async () => {
  const { router } = renderRoute('/o/acme/certificates/c-1/edit');
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-1/overview'));
});

it('marks a keyless version with a No key chip in the Versions tab', async () => {
  versions = [makeVersion({ id: 'v-1', hasKey: false }), makeVersion({ id: 'v-0', serial: '03aa77', hasKey: true })];
  renderRoute('/o/acme/certificates/c-1/versions');
  const table = await screen.findByRole('table', { name: 'Versions' });
  await within(table).findByText('No key');
  const rows = within(table).getAllByRole('row').slice(1);
  expect(within(rows[0]!).getByText('No key')).toBeInTheDocument();
  expect(within(rows[1]!).queryByText('No key')).not.toBeInTheDocument();
});

// Fix wave (Important): an uploaded/imported certificate's own
// verificationRules is empty (upload/import never runs the wizard), so
// Coverage's "first matching rule" search finds none for any name — a
// false "No matching rule" for a certificate that was never meant to be
// verified by CertForge at all. Coverage and the Verification summary only
// make sense for a certificate CertForge itself renews.
it('hides the Coverage panel for an unmanaged certificate on Overview', async () => {
  server.use(http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(makeCert({ managed: false, verificationRules: [] }))));
  renderRoute('/o/acme/certificates/c-1/overview');
  await screen.findByRole('heading', { level: 1, name: 'www' });
  expect(screen.queryByRole('region', { name: 'Coverage' })).not.toBeInTheDocument();
  expect(screen.queryByText('No matching rule')).not.toBeInTheDocument();
});

it('hides the Verification summary and Coverage panel for an unmanaged certificate on Settings', async () => {
  server.use(http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(makeCert({ managed: false, verificationRules: [] }))));
  renderRoute('/o/acme/certificates/c-1/settings');
  await screen.findByRole('heading', { level: 1, name: 'www' });
  expect(screen.queryByRole('heading', { name: 'Verification' })).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Coverage' })).not.toBeInTheDocument();
  expect(screen.queryByText('No matching rule')).not.toBeInTheDocument();
});

// A managed certificate raced to unmanaged server-side (or any other 409):
// useRenewCertificates is meta: { silent: true }, so this proves the header
// still surfaces it via renewToastHandlers instead of failing silently.
it('toasts when Renew now 409s on a certificate that raced to unmanaged', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(makeCert({ managed: true }))),
    http.post(url('/orgs/org-1/certificates/c-1/renew'), () => ((renewCalls += 1), problem(409, 'managed externally'))),
  );
  const { user } = renderRoute('/o/acme/certificates/c-1/overview');
  await user.click(await screen.findByRole('button', { name: 'Renew now' }));
  expect(await screen.findByText('Renewal failed for www.')).toBeInTheDocument();
  expect(renewCalls).toBe(1);
});
