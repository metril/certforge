import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, ca, makeCert, problem, providers, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let created: unknown;
let updated: unknown;
beforeEach(() => {
  created = undefined;
  updated = undefined;
  localStorage.clear();
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json([{ id: 'd-1', name: 'Cloudflare prod', providerCode: 'cloudflare', config: {} }])),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: providers, deployTargets: [], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/certificates'), () => HttpResponse.json({ items: [makeCert()], nextCursor: null })),
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json({ caId: { value: 'ca-1', source: 'org' } })),
    http.get(url('/orgs/org-1/issuance-defaults'), () => HttpResponse.json({ caId: 'ca-1' })),
    http.get(url('/settings/issuance_defaults'), () => HttpResponse.json({ schema: {}, value: {} })),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.post(url('/orgs/org-1/certificates'), async ({ request }) => {
      created = await request.json();
      return HttpResponse.json(makeCert({ id: 'c-new', name: 'www.example.com', status: 'pending', currentVersion: undefined }), { status: 201 });
    }),
    // Task 16: submitting lands on the certificate's own detail route, which
    // (unlike the route stub these tests originally landed on) actually
    // fetches the certificate by id.
    http.get(url('/orgs/org-1/certificates/c-new'), () =>
      HttpResponse.json(makeCert({ id: 'c-new', name: 'www.example.com', status: 'pending', currentVersion: undefined })),
    ),
  );
});

it('fast path: paste names, credential pre-filled, Issue from step 2', async () => {
  const { router, user } = renderRoute('/o/acme/certificates/new');
  await user.click(await screen.findByLabelText('Names'));
  await user.paste('www.example.com *.example.com');
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toHaveTextContent('Cloudflare prod'));
  const rail = screen.getByRole('complementary', { name: 'Summary' });
  expect(within(rail).getByText('2 of 2 names')).toBeInTheDocument();
  expect(within(rail).getByText("Let's Encrypt")).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await waitFor(() =>
    expect(created).toEqual({
      name: 'www.example.com',
      commonName: 'www.example.com',
      sans: ['www.example.com', '*.example.com'],
      verificationRules: [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1', via: 'server' }],
      overrides: {},
    }),
  );
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-new/attempts'));
  // rememberFromRules ran exactly once on success (fix round: not on every
  // keystroke) — the end state has exactly the one zone->credential entry
  // this create's own rules produced, nothing left over or duplicated.
  expect(JSON.parse(localStorage.getItem('cf-last-cred') ?? '{}')).toEqual({ 'example.com': 'd-1' });
  // Task 16: let the certificate detail page itself settle (it fires its
  // own queries) before the test ends, instead of leaving them in flight
  // into the next test's handler reset.
  await screen.findByRole('navigation', { name: 'Breadcrumb' });
});

it('blocks Issue while a zone has no credential and no catch-all', async () => {
  const { user } = renderRoute('/o/acme/certificates/new');
  await user.click(await screen.findByLabelText('Names'));
  await user.paste('api.other.net');
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(screen.getByLabelText('Rule 1 match')).toHaveValue('other.net'));
  expect(screen.getByRole('button', { name: 'Issue certificate' })).toBeDisabled();
  expect(within(screen.getByRole('complementary', { name: 'Summary' })).getByText('0 of 1 names')).toBeInTheDocument();
});

it('reviews effective options with their source before issuing', async () => {
  const { user } = renderRoute('/o/acme/certificates/new');
  await user.click(await screen.findByLabelText('Names'));
  await user.paste('www.example.com');
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toHaveTextContent('Cloudflare prod'));
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await user.click(screen.getByRole('switch', { name: 'Override Key type' }));
  await user.click(screen.getByRole('radio', { name: 'RSA 2048' }));
  await user.click(screen.getByRole('button', { name: 'Review' }));
  const options = screen.getByRole('region', { name: 'Options' });
  expect(within(options).getByText('RSA 2048')).toBeInTheDocument();
  expect(within(options).getAllByRole('button', { name: 'Cert' })).toHaveLength(1);
  expect(within(options).getAllByRole('button', { name: 'Org' }).length).toBeGreaterThan(0);
});

// I3 (Important, Task 10 ruling): OptionsStep must build the Global level of
// each field's inheritance chain from the settings section's `stored` (the
// raw saved document), not its `value` (built-in-filled for display) —
// otherwise a field whose badge reads "Default" (nothing overrides it
// anywhere) would still claim, in its tooltip, an inherited "Global: EC
// P-256" that Global never actually set.
it("a field with source 'default' never claims a Global value the section's stored document doesn't have", async () => {
  server.use(
    http.get(url('/settings/issuance_defaults'), () => HttpResponse.json({ schema: {}, value: { keyType: 'ec256' }, stored: {} })),
  );
  const { user } = renderRoute('/o/acme/certificates/new');
  await user.click(await screen.findByLabelText('Names'));
  await user.paste('www.example.com');
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toHaveTextContent('Cloudflare prod'));
  await user.click(screen.getByRole('button', { name: 'Next' }));
  const keyType = screen.getByRole('group', { name: 'Key type' });
  expect(within(keyType).getByRole('button', { name: 'Default' })).toBeInTheDocument();
  await user.hover(within(keyType).getByRole('button', { name: 'Default' }));
  const tooltip = await screen.findByRole('tooltip');
  expect(tooltip).toHaveTextContent('Global: server default');
  expect(tooltip).not.toHaveTextContent('EC P-256');
});

it('disables Next on the Names step until a valid name and common name exist', async () => {
  const { user } = renderRoute('/o/acme/certificates/new');
  await screen.findByLabelText('Names');
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
  await user.click(screen.getByLabelText('Names'));
  await user.paste('www.example.com');
  expect(screen.getByRole('button', { name: 'Next' })).not.toBeDisabled();
});

it('a 422 on issue sends the user back to the step that owns the field, with the detail inline, and clears on the next edit', async () => {
  server.use(
    http.post(url('/orgs/org-1/certificates'), () => problem(422, 'rule example.com: no such DNS credential in this org', {}, 'Invalid verificationRules')),
  );
  const { user } = renderRoute('/o/acme/certificates/new');
  await user.click(await screen.findByLabelText('Names'));
  await user.paste('www.example.com');
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toHaveTextContent('Cloudflare prod'));
  await user.click(screen.getByRole('button', { name: 'Next' })); // -> Options
  await user.click(screen.getByRole('button', { name: 'Review' })); // -> Review
  await user.click(screen.getByRole('button', { name: 'Issue certificate' }));
  // Landed back on Verification (step 2 of 4), which owns `verificationRules`.
  await waitFor(() => expect(screen.getByText(/no such DNS credential/)).toBeInTheDocument());
  expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toBeInTheDocument();
  // Fix round 1 (review, Important #2): any further edit clears the banner,
  // not just the next submit attempt.
  await user.type(screen.getByLabelText('Rule 1 match'), 'x');
  expect(screen.queryByText(/no such DNS credential/)).not.toBeInTheDocument();
});

it('shows a banner on Review for an error that maps to no field, and never remembers a credential on failure', async () => {
  server.use(http.post(url('/orgs/org-1/certificates'), () => problem(500, 'Something broke.', {}, 'Internal error')));
  const { user } = renderRoute('/o/acme/certificates/new');
  await user.click(await screen.findByLabelText('Names'));
  await user.paste('www.example.com');
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toHaveTextContent('Cloudflare prod'));
  await user.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await waitFor(() => expect(screen.getByText('Something broke.')).toBeInTheDocument());
  expect(screen.getByRole('region', { name: 'Options' })).toBeInTheDocument(); // landed on Review
  // Fix round 1 (review, take-now #7): a failed create must not leave a
  // stale credential mapping behind.
  expect(localStorage.getItem('cf-last-cred')).toBeNull();
  // Fix round 1 (review, Important #2): stepping back (any navigation, not
  // just an edit) also clears the banner.
  await user.click(screen.getByRole('button', { name: 'Back' }));
  expect(screen.queryByText('Something broke.')).not.toBeInTheDocument();
});

it('edit mode: a common-name-only change (same set of names) still shows the reissue notice', async () => {
  // M1: a GET response's sans is `names[1:]` — it never repeats the common
  // name — so this certificate's one additional SAN is 'api.example.com'.
  server.use(http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(makeCert({ sans: ['api.example.com'] }))));
  const { user } = renderRoute('/o/acme/certificates/c-1/edit');
  await user.click(await screen.findByLabelText('Names'));
  expect(screen.queryByText(/will issue a new certificate/i)).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Make api.example.com the common name' }));
  expect(screen.getByText(/will issue a new certificate/i)).toBeInTheDocument();
});

it('edit mode: an untouched save keeps overrides, remembers no credential, and lands on Overview', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(makeCert({ overrides: { keyType: 'rsa2048' } }))),
    http.put(url('/orgs/org-1/certificates/c-1'), async ({ request }) => {
      updated = await request.json();
      return HttpResponse.json(makeCert({ overrides: { keyType: 'rsa2048' } }));
    }),
  );
  const { router, user } = renderRoute('/o/acme/certificates/c-1/edit');
  await user.click(await screen.findByLabelText('Names'));
  expect(screen.queryByText(/will issue a new certificate/i)).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toHaveTextContent('Cloudflare prod'));
  await user.click(screen.getByRole('button', { name: 'Save changes' }));
  await waitFor(() =>
    expect(updated).toMatchObject({
      commonName: 'www.example.com',
      sans: ['www.example.com'],
      overrides: { keyType: 'rsa2048' },
    }),
  );
  // Fix round 1 (review, Important #3): rules never changed, so nothing new is remembered.
  expect(localStorage.getItem('cf-last-cred')).toBeNull();
  // Fix round 1 (review, take-now #6): no name change -> no new issuance -> Overview, not Attempts.
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-1/overview'));
  // Task 16: let the certificate detail page itself settle before the test ends.
  await screen.findByRole('navigation', { name: 'Breadcrumb' });
});

it('edit mode: changing a rule credential (names unchanged) remembers it and still lands on Overview', async () => {
  server.use(
    http.get(url('/orgs/org-1/dns-credentials'), () =>
      HttpResponse.json([
        { id: 'd-1', name: 'Cloudflare prod', providerCode: 'cloudflare', config: {} },
        { id: 'd-2', name: 'Cloudflare prod 2', providerCode: 'cloudflare', config: {} },
      ]),
    ),
    http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(makeCert())),
    http.put(url('/orgs/org-1/certificates/c-1'), async ({ request }) => {
      updated = await request.json();
      return HttpResponse.json(makeCert());
    }),
  );
  const { router, user } = renderRoute('/o/acme/certificates/c-1/edit');
  await user.click(await screen.findByLabelText('Names'));
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toHaveTextContent('Cloudflare prod'));
  await user.click(screen.getByRole('combobox', { name: 'Rule 1 credential' }));
  await user.click(await screen.findByText('Cloudflare prod 2'));
  await user.click(screen.getByRole('button', { name: 'Save changes' }));
  await waitFor(() => expect(updated).toMatchObject({ verificationRules: [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-2' }] }));
  expect(JSON.parse(localStorage.getItem('cf-last-cred') ?? '{}')).toEqual({ 'example.com': 'd-2' });
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-1/overview'));
  // Task 16: let the certificate detail page itself settle before the test ends.
  await screen.findByRole('navigation', { name: 'Breadcrumb' });
});

it('edit mode: a name change reissues, PUTs, and lands on Attempts', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(makeCert())),
    http.put(url('/orgs/org-1/certificates/c-1'), async ({ request }) => {
      updated = await request.json();
      // M1: the PUT response's sans is also `names[1:]`, same as any GET.
      return HttpResponse.json(makeCert({ sans: ['api.example.com'] }));
    }),
  );
  const { router, user } = renderRoute('/o/acme/certificates/c-1/edit');
  await user.click(await screen.findByLabelText('Names'));
  expect(screen.getAllByText('www.example.com').length).toBeGreaterThan(0);
  await user.paste('api.example.com');
  expect(screen.getByText(/will issue a new certificate/i)).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toHaveTextContent('Cloudflare prod'));
  await user.click(screen.getByRole('button', { name: 'Save changes' }));
  await waitFor(() => expect(updated).toMatchObject({ commonName: 'www.example.com', sans: ['www.example.com', 'api.example.com'] }));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-1/attempts'));
  // Task 16: let the certificate detail page itself settle before the test ends.
  await screen.findByRole('navigation', { name: 'Breadcrumb' });
});
