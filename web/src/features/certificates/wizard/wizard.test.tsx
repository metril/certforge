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
      verificationRules: [{ match: 'example.com', method: 'dns-01', dnsCredentialId: 'd-1' }],
      overrides: {},
    }),
  );
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-new/attempts'));
  // rememberFromRules ran once on success (fix round: not on every keystroke).
  expect(JSON.parse(localStorage.getItem('cf-last-cred') ?? '{}')).toEqual({ 'example.com': 'd-1' });
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

it('disables Next on the Names step until a valid name and common name exist', async () => {
  const { user } = renderRoute('/o/acme/certificates/new');
  await screen.findByLabelText('Names');
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
  await user.click(screen.getByLabelText('Names'));
  await user.paste('www.example.com');
  expect(screen.getByRole('button', { name: 'Next' })).not.toBeDisabled();
});

it('a 422 on issue sends the user back to the step that owns the field, with the detail inline', async () => {
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
});

it('shows a banner on Review for an error that maps to no field', async () => {
  server.use(http.post(url('/orgs/org-1/certificates'), () => problem(500, 'Something broke.', {}, 'Internal error')));
  const { user } = renderRoute('/o/acme/certificates/new');
  await user.click(await screen.findByLabelText('Names'));
  await user.paste('www.example.com');
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule 1 credential' })).toHaveTextContent('Cloudflare prod'));
  await user.click(screen.getByRole('button', { name: 'Issue certificate' }));
  await waitFor(() => expect(screen.getByText('Something broke.')).toBeInTheDocument());
  expect(screen.getByRole('region', { name: 'Options' })).toBeInTheDocument(); // landed on Review
});

it('edit mode: loads the certificate, notes a name change, and PUTs', async () => {
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(makeCert())),
    http.put(url('/orgs/org-1/certificates/c-1'), async ({ request }) => {
      updated = await request.json();
      return HttpResponse.json(makeCert({ sans: ['www.example.com', 'api.example.com'] }));
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
});
