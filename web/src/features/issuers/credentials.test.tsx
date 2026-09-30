import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import type { DnsCredential } from '@/api/types';
import { UNCHANGED } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, meWith, problem, providers, url } from '@/test/fixtures';
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

// Fix round 1 (take-now #4): the loading state is a row inside the table,
// not a bare paragraph outside it (keeps the column layout stable).
it('shows the loading state as a row inside the table', async () => {
  creds = [cred];
  renderRoute('/o/acme/issuers/dns');
  const loading = await screen.findByText('Loading…');
  expect(loading.closest('table')).not.toBeNull();
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

// Fix round 1: click the disabled option itself (not just assert the
// attribute) and confirm nothing was picked — the picker stays open with no
// credential sheet behind it.
it('clicking an unsupported provider option does not pick it', async () => {
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Add credential' }));
  const opt = await screen.findByRole('option', { name: /HyperOne/ });
  expect(opt).toHaveAttribute('aria-disabled', 'true');
  await user.click(opt);
  expect(screen.getByRole('combobox')).toBeInTheDocument();
  expect(screen.queryByRole('dialog', { name: /^Add /i })).not.toBeInTheDocument();
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
  expect(within(sheet).getByLabelText('CLOUDFLARE_TTL')).toHaveValue('300');
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

// Fix round 1 (Important): RJSF keeps `{key: undefined}` in formData when a
// field is cleared; String(undefined) is the literal string "undefined",
// which must never reach the request body.
it('omits a cleared optional field instead of sending the string "undefined"', async () => {
  creds = [{ ...cred, config: { CLOUDFLARE_TTL: '300', CLOUDFLARE_PROPAGATION_TIMEOUT: '60' } }];
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Edit Cloudflare prod' }));
  const sheet = await screen.findByRole('dialog', { name: 'Edit Cloudflare prod' });
  await user.clear(within(sheet).getByLabelText('CLOUDFLARE_PROPAGATION_TIMEOUT'));
  await user.click(within(sheet).getByRole('button', { name: 'Save credential' }));
  await waitFor(() => expect(put).toBeDefined());
  const body = put as { config: Record<string, string> };
  expect(body.config).not.toHaveProperty('CLOUDFLARE_PROPAGATION_TIMEOUT');
  expect(Object.values(body.config)).not.toContain('undefined');
});

it('shows no re-entry notice on open, or after a no-op edit', async () => {
  creds = [cred];
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Edit Cloudflare prod' }));
  const sheet = await screen.findByRole('dialog', { name: 'Edit Cloudflare prod' });
  expect(within(sheet).queryByText(/must be re-entered/i)).not.toBeInTheDocument();
  await user.click(within(sheet).getByLabelText('CLOUDFLARE_TTL'));
  await user.tab();
  expect(within(sheet).queryByText(/must be re-entered/i)).not.toBeInTheDocument();
});

it('"Change provider" starts the new provider\'s form fresh', async () => {
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Add credential' }));
  await user.type(screen.getByRole('combobox'), 'cloudflare');
  await user.click(screen.getByRole('option', { name: /Cloudflare/ }));
  let sheet = await screen.findByRole('dialog', { name: 'Add Cloudflare credential' });
  await user.type(within(sheet).getByLabelText('CF_DNS_API_TOKEN'), 'tok');
  await user.click(within(sheet).getByRole('button', { name: 'Change provider' }));
  await user.type(screen.getByRole('combobox'), 'route53');
  await user.click(screen.getByRole('option', { name: /Amazon Route 53/ }));
  sheet = await screen.findByRole('dialog', { name: 'Add Amazon Route 53 credential' });
  expect(within(sheet).queryByLabelText('CF_DNS_API_TOKEN')).not.toBeInTheDocument();
  expect(within(sheet).getByLabelText('Access key ID')).toHaveValue('');
});

it('shows a form-level error when saving fails with a non-API error', async () => {
  server.use(http.post(url('/orgs/org-1/dns-credentials'), () => HttpResponse.error()));
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Add credential' }));
  await user.type(screen.getByRole('combobox'), 'cloudflare');
  await user.click(screen.getByRole('option', { name: /Cloudflare/ }));
  const sheet = await screen.findByRole('dialog', { name: 'Add Cloudflare credential' });
  await user.type(within(sheet).getByLabelText('CF_DNS_API_TOKEN'), 'tok');
  await user.click(within(sheet).getByRole('button', { name: 'Save credential' }));
  expect(await within(sheet).findByRole('alert')).toBeInTheDocument();
});

// Fix round 1 (take-now #3): a pasted URL is normalized to a bare hostname.
it('normalizes a pasted URL to a bare zone before testing', async () => {
  creds = [cred];
  const { user } = renderRoute('/o/acme/issuers/dns');
  const row = (await screen.findByText('Cloudflare prod')).closest('tr')!;
  await user.click(within(row).getByRole('button', { name: 'Test Cloudflare prod' }));
  const dialog = screen.getByRole('dialog', { name: 'Test Cloudflare prod' });
  await user.type(within(dialog).getByLabelText('Zone'), 'https://example.com/');
  await user.click(within(dialog).getByRole('button', { name: 'Run test' }));
  await waitFor(() => expect(tested).toEqual({ zone: 'example.com' }));
  expect(await within(dialog).findByText('Works for example.com')).toBeInTheDocument();
});

it('rejects a zone with spaces instead of sending it', async () => {
  creds = [cred];
  const { user } = renderRoute('/o/acme/issuers/dns');
  const row = (await screen.findByText('Cloudflare prod')).closest('tr')!;
  await user.click(within(row).getByRole('button', { name: 'Test Cloudflare prod' }));
  const dialog = screen.getByRole('dialog', { name: 'Test Cloudflare prod' });
  await user.type(within(dialog).getByLabelText('Zone'), 'exa mple.com');
  expect(within(dialog).getByRole('button', { name: 'Run test' })).toBeDisabled();
  expect(within(dialog).getByText('Enter a valid hostname')).toBeInTheDocument();
  expect(tested).toBeUndefined();
});

// Fix round 1 (take-now #6): the disabled Edit button (unknown/loading
// provider) explains why.
it('disables Edit with a tooltip for a credential whose provider is unknown', async () => {
  creds = [{ ...cred, providerCode: 'not-a-real-provider' }];
  const { user } = renderRoute('/o/acme/issuers/dns');
  const edit = await screen.findByRole('button', { name: 'Edit Cloudflare prod' });
  expect(edit).toBeDisabled();
  await user.hover(edit);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Unknown provider "not-a-real-provider"');
});

// Fix round 2 (Important #1): a viewer has dnscreds:read but not
// dnscreds:write — Add credential, Test, Edit and Delete stay visible but
// disabled, independent of the credential's own usedBy-based Delete gate.
it('disables Add/Test/Edit/Delete for a viewer', async () => {
  creds = [{ ...cred, usedBy: 0 }];
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: 'org-1' }]))));
  renderRoute('/o/acme/issuers/dns');
  expect(await screen.findByRole('button', { name: 'Add credential' })).toBeDisabled();
  expect(screen.getByRole('button', { name: `Test ${cred.name}` })).toBeDisabled();
  expect(screen.getByRole('button', { name: `Edit ${cred.name}` })).toBeDisabled();
  expect(screen.getByRole('button', { name: `Delete ${cred.name}` })).toBeDisabled();
});

async function openAddCloudflare() {
  const r = renderRoute('/o/acme/issuers/dns');
  await r.user.click(await screen.findByRole('button', { name: 'Add credential' }));
  await r.user.type(screen.getByRole('combobox'), 'cloudfl');
  await r.user.click(screen.getByRole('option', { name: /Cloudflare/ }));
  const sheet = await screen.findByRole('dialog', { name: 'Add Cloudflare credential' });
  return { user: r.user, sheet };
}

it('shows only the default method fields and never alias fields', async () => {
  const { sheet } = await openAddCloudflare();
  expect(within(sheet).getByLabelText('CF_DNS_API_TOKEN')).toBeInTheDocument();
  expect(within(sheet).getByLabelText('CF_ZONE_API_TOKEN')).toBeInTheDocument();
  expect(within(sheet).queryByLabelText('CF_API_KEY')).not.toBeInTheDocument();
  expect(within(sheet).queryByLabelText('CLOUDFLARE_API_KEY')).not.toBeInTheDocument();
});

it('switching method hides the other method fields and omits them on save', async () => {
  const { user, sheet } = await openAddCloudflare();
  await user.type(within(sheet).getByLabelText('CF_DNS_API_TOKEN'), 'tok');
  await user.click(within(sheet).getByRole('radio', { name: 'Email + API key' }));
  expect(within(sheet).queryByLabelText('CF_DNS_API_TOKEN')).not.toBeInTheDocument();
  await user.type(within(sheet).getByLabelText('CF_API_EMAIL'), 'a@b.c');
  await user.type(within(sheet).getByLabelText('CF_API_KEY'), 'key');
  await user.click(within(sheet).getByRole('button', { name: 'Save credential' }));
  await waitFor(() =>
    expect(posted).toEqual({ name: 'Cloudflare', providerCode: 'cloudflare', config: { CF_API_EMAIL: 'a@b.c', CF_API_KEY: 'key' } }),
  );
});

it('blocks save while a required method field is empty', async () => {
  const { user, sheet } = await openAddCloudflare();
  await user.click(within(sheet).getByRole('button', { name: 'Save credential' }));
  await new Promise((r) => setTimeout(r, 50));
  expect(posted).toBeUndefined();
  expect(await within(sheet).findByRole('alert')).toBeInTheDocument();
});

it('editing with a stored CF_API_KEY opens on the email + key method', async () => {
  creds = [{ ...cred, config: { CF_API_EMAIL: 'a@b.c' }, storedSecrets: ['CF_API_KEY'] }];
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Edit Cloudflare prod' }));
  const sheet = await screen.findByRole('dialog', { name: 'Edit Cloudflare prod' });
  expect(within(sheet).getByLabelText('CF_API_EMAIL')).toHaveValue('a@b.c');
  expect(within(sheet).getByText('CF_API_KEY')).toBeInTheDocument();
  expect(within(sheet).queryByText('CF_DNS_API_TOKEN')).not.toBeInTheDocument();
  expect(within(sheet).queryByLabelText('CF_DNS_API_TOKEN')).not.toBeInTheDocument();
});

it('keeps Advanced closed by default and open when an advanced value is set', async () => {
  const { sheet } = await openAddCloudflare();
  expect(within(sheet).queryByLabelText('CLOUDFLARE_TTL')).not.toBeInTheDocument();
  expect(within(sheet).getByRole('button', { name: 'Advanced' })).toBeInTheDocument();
});

it('opens Advanced when a stored advanced value exists', async () => {
  creds = [cred];
  const { user } = renderRoute('/o/acme/issuers/dns');
  await user.click(await screen.findByRole('button', { name: 'Edit Cloudflare prod' }));
  const sheet = await screen.findByRole('dialog', { name: 'Edit Cloudflare prod' });
  expect(within(sheet).getByLabelText('CLOUDFLARE_TTL')).toBeInTheDocument();
});

it('shows no method switcher for a provider without auth methods', async () => {
  const r = renderRoute('/o/acme/issuers/dns');
  await r.user.click(await screen.findByRole('button', { name: 'Add credential' }));
  await r.user.type(screen.getByRole('combobox'), 'route53');
  await r.user.click(screen.getByRole('option', { name: /Amazon Route 53/ }));
  const sheet = await screen.findByRole('dialog', { name: 'Add Amazon Route 53 credential' });
  expect(within(sheet).queryByText('Authenticate with')).not.toBeInTheDocument();
});
