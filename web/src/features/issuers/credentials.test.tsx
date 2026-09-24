import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import type { DnsCredential } from '@/api/types';
import { UNCHANGED } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, problem, providers, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// preflight A12: every real provider config property (and DNSCredential.config)
// is a plain string, so the fixture below mirrors cloudflare.json's own field
// names instead of the brief's made-up `ttl: 300`/`apiToken`/`zoneToken`.
const cred: DnsCredential = {
  id: 'd-1',
  name: 'Cloudflare prod',
  providerCode: 'cloudflare',
  config: { CLOUDFLARE_TTL: '300' },
  storedSecrets: ['CF_DNS_API_TOKEN', 'CF_ZONE_API_TOKEN'],
  usedBy: 2,
};

let creds: DnsCredential[];
let posted: unknown;
let put: unknown;
let deleted: string | undefined;
let tested: unknown;

beforeEach(() => {
  creds = [];
  posted = put = tested = deleted = undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: providers, deployTargets: [], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json(creds)),
    http.post(url('/orgs/org-1/dns-credentials'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json({ ...(posted as object), id: 'd-9' }, { status: 201 });
    }),
    // preflight A17: PUT sends DNSCredentialUpdate {name, config} — no providerCode.
    http.put(url('/orgs/org-1/dns-credentials/:id'), async ({ request }) => {
      put = await request.json();
      return HttpResponse.json({ ...cred, ...(put as object) });
    }),
    http.delete(url('/orgs/org-1/dns-credentials/:id'), ({ params }) => {
      deleted = String(params.id);
      return problem(409, 'DNS credential is used by 2 certificates', {}, 'In use');
    }),
    http.post(url('/orgs/org-1/dns-credentials/:id/test'), async ({ request }) => {
      tested = await request.json();
      return HttpResponse.json({ ok: true, fqdn: '_acme-challenge.example.com', durationMs: 420 });
    }),
  );
});

it('adds a credential through the provider picker', async () => {
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Add credential' }));
  await user.type(screen.getByRole('combobox'), 'cloudfl');
  await user.click(screen.getByRole('option', { name: /Cloudflare/ }));
  const sheet = await screen.findByRole('dialog', { name: 'Add Cloudflare credential' });
  await user.clear(within(sheet).getByLabelText('Name'));
  await user.type(within(sheet).getByLabelText('Name'), 'Cloudflare prod');
  await user.type(within(sheet).getByLabelText('CF_DNS_API_TOKEN'), 'tok');
  await user.click(within(sheet).getByRole('button', { name: 'Save credential' }));
  await waitFor(() => expect(posted).toEqual({ name: 'Cloudflare prod', providerCode: 'cloudflare', config: { CF_DNS_API_TOKEN: 'tok' } }));
});

it('does not open a sheet for an unsupported provider from the credentials page picker', async () => {
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Add credential' }));
  const opt = await screen.findByRole('option', { name: /HyperOne/ });
  expect(opt).toHaveAttribute('aria-disabled', 'true');
  expect(screen.queryByRole('dialog', { name: /Add HyperOne/ })).not.toBeInTheDocument();
});

it('editing keeps stored secrets that were replaced then reverted, sending DNSCredentialUpdate with no providerCode', async () => {
  creds = [cred];
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Edit Cloudflare prod' }));
  const sheet = await screen.findByRole('dialog', { name: 'Edit Cloudflare prod' });
  await user.click(within(sheet).getAllByRole('button', { name: /Replace/ })[0]!);
  await user.type(within(sheet).getByLabelText('CF_DNS_API_TOKEN'), 'oops');
  await user.click(within(sheet).getByRole('button', { name: /Keep stored/ }));
  await user.type(within(sheet).getByLabelText('Name'), ' 2');
  await user.click(within(sheet).getByRole('button', { name: 'Save credential' }));
  await waitFor(() =>
    expect(put).toEqual({ name: 'Cloudflare prod 2', config: { CLOUDFLARE_TTL: '300', CF_DNS_API_TOKEN: UNCHANGED, CF_ZONE_API_TOKEN: UNCHANGED } }),
  );
});

// Controller ruling: changing a public (non-secret) config value while a
// secret is still stored/untouched warns before submit, and the server's own
// 422 (internal/issuance/store_dnscreds.go) surfaces next to the form if it
// still gets through.
it('warns that stored secrets must be re-entered after a public field changes, and shows the 422 if it still fails', async () => {
  creds = [cred];
  server.use(http.put(url('/orgs/org-1/dns-credentials/:id'), () => problem(422, 'secrets must be re-entered when connection settings change', {}, 'Invalid config')));
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Edit Cloudflare prod' }));
  const sheet = await screen.findByRole('dialog', { name: 'Edit Cloudflare prod' });
  await user.clear(within(sheet).getByLabelText('CLOUDFLARE_TTL'));
  await user.type(within(sheet).getByLabelText('CLOUDFLARE_TTL'), '600');
  expect(within(sheet).getByText(/stored secrets/i)).toBeInTheDocument();
  await user.click(within(sheet).getByRole('button', { name: 'Save credential' }));
  expect(await within(sheet).findByRole('alert')).toHaveTextContent('secrets must be re-entered when connection settings change');
});

it('shows usage from the API and tests a credential against a zone', async () => {
  creds = [cred];
  const { user } = renderRoute('/o/acme/issuers/dns');
  const row = (await screen.findByText('Cloudflare prod')).closest('tr')!;
  expect(await within(row).findByText('Used by 2')).toBeInTheDocument();
  await user.click(within(row).getByRole('button', { name: 'Test Cloudflare prod' }));
  const dialog = screen.getByRole('dialog', { name: 'Test Cloudflare prod' });
  await user.type(within(dialog).getByLabelText('Zone'), 'example.com');
  await user.click(within(dialog).getByRole('button', { name: 'Run test' }));
  expect(await within(dialog).findByText('Works for example.com')).toBeInTheDocument();
  expect(tested).toEqual({ zone: 'example.com' });
});

// preflight A15 (Critical): a 200 with ok:false is a failure, not a success —
// the scrubbed provider error must render, not "Works for ...".
it('shows the scrubbed provider error when the test comes back ok:false', async () => {
  creds = [cred];
  server.use(
    http.post(url('/orgs/org-1/dns-credentials/:id/test'), () =>
      HttpResponse.json({ ok: false, error: 'authentication failed', fqdn: '', durationMs: 150 }),
    ),
  );
  const { user } = renderRoute('/o/acme/issuers/dns');
  const row = (await screen.findByText('Cloudflare prod')).closest('tr')!;
  await user.click(within(row).getByRole('button', { name: 'Test Cloudflare prod' }));
  const dialog = screen.getByRole('dialog', { name: 'Test Cloudflare prod' });
  await user.type(within(dialog).getByLabelText('Zone'), 'example.com');
  await user.click(within(dialog).getByRole('button', { name: 'Run test' }));
  expect(await within(dialog).findByText('authentication failed')).toBeInTheDocument();
  expect(within(dialog).queryByText(/Works for/)).not.toBeInTheDocument();
});

// preflight A16: a 503 from the test semaphore carries Retry-After; errorMessage appends "Retry in Ns."
it('shows a Retry-After hint when the test semaphore is full', async () => {
  creds = [cred];
  server.use(http.post(url('/orgs/org-1/dns-credentials/:id/test'), () => problem(503, 'Too many DNS credential tests are running.', { 'Retry-After': '5' }, 'Service busy')));
  const { user } = renderRoute('/o/acme/issuers/dns');
  const row = (await screen.findByText('Cloudflare prod')).closest('tr')!;
  await user.click(within(row).getByRole('button', { name: 'Test Cloudflare prod' }));
  const dialog = screen.getByRole('dialog', { name: 'Test Cloudflare prod' });
  await user.type(within(dialog).getByLabelText('Zone'), 'example.com');
  await user.click(within(dialog).getByRole('button', { name: 'Run test' }));
  expect(await within(dialog).findByText(/Retry in 5s\./)).toBeInTheDocument();
});

// D13: a credential still referenced (usedBy > 0) has its Delete button
// disabled up front, with the count in a tooltip, rather than only failing
// after the confirm dialog.
it('disables Delete and explains why while the credential is still referenced', async () => {
  creds = [cred];
  const { user } = renderRoute('/o/acme/issuers/dns');
  const del = await screen.findByRole('button', { name: 'Delete Cloudflare prod' });
  expect(del).toBeDisabled();
  await user.hover(del);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Used by 2');
});

it('shows a 409 detail inline when a delete is blocked by a stale usedBy', async () => {
  creds = [{ ...cred, usedBy: 0 }];
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Delete Cloudflare prod' }));
  const dialog = screen.getByRole('dialog');
  await user.type(within(dialog).getByRole('textbox'), 'Cloudflare prod');
  await user.click(within(dialog).getByRole('button', { name: 'Delete credential' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('DNS credential is used by 2 certificates');
  expect(deleted).toBe('d-1');
});
