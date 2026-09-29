import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import type { CA, CAInput } from '@/api/types';
import { UNCHANGED } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, ca, caLocal, caVaultPki, meWith, metaSigners, presets, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let cas: CA[];
let posted: unknown;
let put: CAInput | undefined;
beforeEach(() => {
  cas = [];
  posted = put = undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/ca-presets'), () => HttpResponse.json(presets)),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json(cas)),
    // Fix round 1 (#8): return a proper CA (hasEab, no eabHmac) instead of
    // echoing the CAInput request body back verbatim.
    http.post(url('/orgs/org-1/cas'), async ({ request }) => {
      posted = await request.json();
      const body = posted as CAInput;
      return HttpResponse.json(
        {
          id: 'ca-9',
          name: body.name,
          preset: body.preset,
          directoryUrl: body.directoryUrl,
          trustBundlePem: body.trustBundlePem,
          eabKid: body.eabKid,
          hasEab: !!body.eabKid,
          resolvers: body.resolvers ?? [],
        },
        { status: 201 },
      );
    }),
    http.put(url('/orgs/org-1/cas/:id'), async ({ request, params }) => {
      put = (await request.json()) as CAInput;
      return HttpResponse.json({
        id: String(params.id),
        name: put.name,
        preset: put.preset,
        directoryUrl: put.directoryUrl,
        trustBundlePem: put.trustBundlePem,
        eabKid: put.eabKid,
        hasEab: !!put.eabKid,
        resolvers: put.resolvers ?? [],
      });
    }),
    http.delete(url('/orgs/org-1/cas/:id'), () => problem(409, 'CA is used by 2 certificates')),
  );
});

it('adds a CA from a preset card', async () => {
  const { router, user } = renderRoute('/o/acme/issuers/cas');
  await user.click(await screen.findByRole('button', { name: 'Add CA' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  await user.click(await within(sheet).findByRole('button', { name: /Let's Encrypt \(staging\)/ }));
  expect(within(sheet).getByLabelText('Name')).toHaveValue("Let's Encrypt (staging)");
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  await waitFor(() =>
    expect(posted).toEqual({ name: "Let's Encrypt (staging)", type: 'acme', preset: 'letsencrypt-staging', directoryUrl: presets[1]!.directoryUrl, resolvers: [] }),
  );
  await waitFor(() => expect(router.state.location.search).toEqual({}));
});

// preflight A20: presets includes a `custom` entry with directoryUrl: '' —
// the sheet must not crash rendering its card, and Custom must not appear twice.
it('renders the custom preset once, without crashing on its empty directory URL', async () => {
  const { user } = renderRoute('/o/acme/issuers/cas');
  await user.click(await screen.findByRole('button', { name: 'Add CA' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  expect(await within(sheet).findAllByRole('button', { name: /Custom/ })).toHaveLength(1);
});

it('requires a directory URL for the custom preset', async () => {
  const { user } = renderRoute('/o/acme/issuers/cas');
  await user.click(await screen.findByRole('button', { name: 'Add CA' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  await user.click(await within(sheet).findByRole('button', { name: /^Custom/ }));
  await user.type(within(sheet).getByLabelText('Name'), 'Internal CA');
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  expect(within(sheet).getByText('Use an https:// URL')).toBeInTheDocument();
  expect(posted).toBeUndefined();
});

it('requires EAB for presets that need it', async () => {
  const { user } = renderRoute('/o/acme/issuers/cas?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  await user.click(await within(sheet).findByRole('button', { name: /ZeroSSL/ }));
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  expect(within(sheet).getByText('This CA requires external account binding')).toBeInTheDocument();
  expect(posted).toBeUndefined();
});

// Fix round 1 (#1, Important): a previous preset's EAB kid/HMAC leaked into
// the payload of a preset that doesn't use EAB at all.
it('clears EAB fields when switching from an EAB preset to one that has none', async () => {
  const { user } = renderRoute('/o/acme/issuers/cas');
  await user.click(await screen.findByRole('button', { name: 'Add CA' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  await user.click(await within(sheet).findByRole('button', { name: /ZeroSSL/ }));
  await user.type(within(sheet).getByLabelText('Key ID'), 'kid-1');
  await user.type(within(sheet).getByLabelText('HMAC key'), 'secret-hmac');
  await user.click(within(sheet).getByRole('button', { name: (name) => name.startsWith("Let's Encrypt") && !name.includes('staging') }));
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  await waitFor(() => expect(posted).toBeDefined());
  expect(posted).not.toHaveProperty('eabKid');
  expect(posted).not.toHaveProperty('eabHmac');
});

// Fix round 2: re-clicking the already-selected preset card is not a switch
// and must not wipe EAB values the operator already typed for it.
it('keeps typed EAB values when re-clicking the already-selected preset', async () => {
  const { user } = renderRoute('/o/acme/issuers/cas');
  await user.click(await screen.findByRole('button', { name: 'Add CA' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  const zerossl = await within(sheet).findByRole('button', { name: /ZeroSSL/ });
  await user.click(zerossl);
  await user.type(within(sheet).getByLabelText('Key ID'), 'kid-1');
  await user.type(within(sheet).getByLabelText('HMAC key'), 'secret-hmac');
  await user.click(zerossl);
  expect(within(sheet).getByLabelText('Key ID')).toHaveValue('kid-1');
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  await waitFor(() => expect(posted).toMatchObject({ eabKid: 'kid-1', eabHmac: 'secret-hmac' }));
});

// Fix round 2 (Important): a plain network failure (fetch rejects) is not an
// ApiError; it must still surface as a form-level error, not just stop the
// button spinning silently.
it('shows a form-level error when saving fails with a non-API error', async () => {
  server.use(http.post(url('/orgs/org-1/cas'), () => HttpResponse.error()));
  const { user } = renderRoute('/o/acme/issuers/cas');
  await user.click(await screen.findByRole('button', { name: 'Add CA' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  await user.click(await within(sheet).findByRole('button', { name: (name) => name.startsWith("Let's Encrypt") && !name.includes('staging') }));
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  expect(await within(sheet).findByRole('alert')).toBeInTheDocument();
});

it('keeps a stored EAB HMAC when editing', async () => {
  cas = [{ ...ca, id: 'ca-2', name: 'ZeroSSL', preset: 'zerossl', directoryUrl: presets[2]!.directoryUrl, eabKid: 'kid-1', hasEab: true }];
  const { user } = renderRoute('/o/acme/issuers/cas?edit=ca-2');
  const sheet = await screen.findByRole('dialog', { name: 'Edit ZeroSSL' });
  expect(await within(sheet).findByText('Stored')).toBeInTheDocument();
  await user.clear(within(sheet).getByLabelText('Name'));
  await user.type(within(sheet).getByLabelText('Name'), 'ZeroSSL prod');
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  await waitFor(() => expect(put).toMatchObject({ name: 'ZeroSSL prod', eabKid: 'kid-1', eabHmac: UNCHANGED }));
});

it('replaces a stored EAB HMAC with a new value', async () => {
  cas = [{ ...ca, id: 'ca-2', name: 'ZeroSSL', preset: 'zerossl', directoryUrl: presets[2]!.directoryUrl, eabKid: 'kid-1', hasEab: true }];
  const { user } = renderRoute('/o/acme/issuers/cas?edit=ca-2');
  const sheet = await screen.findByRole('dialog', { name: 'Edit ZeroSSL' });
  await user.click(await within(sheet).findByRole('button', { name: /Replace/ }));
  await user.type(within(sheet).getByLabelText('HMAC key'), 'new-hmac-value');
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  await waitFor(() => expect(put).toMatchObject({ eabKid: 'kid-1', eabHmac: 'new-hmac-value' }));
});

it('removes a stored EAB HMAC when the key id is cleared', async () => {
  cas = [{ ...ca, id: 'ca-3', name: 'Internal CA', preset: 'custom', directoryUrl: 'https://ca.internal/acme/directory', eabKid: 'kid-1', hasEab: true }];
  const { user } = renderRoute('/o/acme/issuers/cas?edit=ca-3');
  const sheet = await screen.findByRole('dialog', { name: 'Edit Internal CA' });
  await user.clear(within(sheet).getByLabelText('Key ID'));
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  await waitFor(() => expect(put).toMatchObject({ eabHmac: '' }));
  expect(put).not.toHaveProperty('eabKid');
});

it('shows why a CA cannot be deleted', async () => {
  cas = [ca];
  const { user } = renderRoute('/o/acme/issuers/cas');
  await user.click(await screen.findByRole('button', { name: "Delete Let's Encrypt" }));
  const dialog = screen.getByRole('dialog');
  await user.type(within(dialog).getByRole('textbox'), "Let's Encrypt");
  await user.click(within(dialog).getByRole('button', { name: 'Delete CA' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('CA is used by 2 certificates');
});

// Fix round 1 (#7): a stale/typo'd ?edit id must not silently render nothing.
it('shows a not-found state for an unknown ?edit id and clears it on Back to CAs', async () => {
  cas = [ca];
  const { router, user } = renderRoute('/o/acme/issuers/cas?edit=nope');
  const dialog = await screen.findByRole('dialog', { name: 'CA not found' });
  await user.click(within(dialog).getByRole('button', { name: 'Back to CAs' }));
  await waitFor(() => expect(router.state.location.search).toEqual({}));
});

// Fix round 1 (#7): closing the editor must replace the history entry, so
// browser Back doesn't land back on the same ?edit=<id> and reopen it.
it('closing the CA editor does not let Back reopen it', async () => {
  cas = [ca];
  const { router, user } = renderRoute('/o/acme/issuers/cas?edit=ca-1');
  const sheet = await screen.findByRole('dialog', { name: "Edit Let's Encrypt" });
  await user.click(within(sheet).getByRole('button', { name: 'Close' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  router.history.back();
  await waitFor(() => expect(router.state.location.search).toEqual({}));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});

// Fix round 2 (Important #1): cas:write is global-only — an org-admin (who
// has every other org-scoped write action) still lacks it, so Add/Edit/
// Delete CA stay visible but disabled.
it('disables Add/Edit/Delete CA for an org-admin (cas:write is global-only)', async () => {
  cas = [ca];
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: 'org-1' }]))));
  renderRoute('/o/acme/issuers/cas');
  expect(await screen.findByRole('button', { name: 'Add CA' })).toBeDisabled();
  expect(screen.getByRole('button', { name: "Edit Let's Encrypt" })).toBeDisabled();
  expect(screen.getByRole('button', { name: "Delete Let's Encrypt" })).toBeDisabled();
});

// Task 2: CA types with built-in and Vault PKI forms.

function withSigners() {
  server.use(http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [], notifiers: [], signers: metaSigners })));
}

it('type chip and endpoint per kind', async () => {
  cas = [ca, caLocal, caVaultPki];
  renderRoute('/o/acme/issuers/cas');
  await screen.findByText(ca.name);
  const rows = screen.getAllByRole('row').slice(1); // drop the header row
  expect(within(rows[0]!).getByText('ACME')).toBeInTheDocument();
  expect(within(rows[0]!).getByText(ca.directoryUrl)).toBeInTheDocument();
  expect(within(rows[1]!).getByText('Built-in CA')).toBeInTheDocument();
  // caLocal's name and its endpoint (subject common name) are both "Internal CA".
  expect(within(rows[1]!).getAllByText('Internal CA')).toHaveLength(2);
  // caVaultPki's name is also literally "Vault PKI" (fixture), same as the kind label.
  expect(within(rows[2]!).getAllByText('Vault PKI')).toHaveLength(2);
  expect(within(rows[2]!).getByText('pki/certforge')).toBeInTheDocument();
});

it('filter by type', async () => {
  cas = [ca, caLocal, caVaultPki];
  renderRoute('/o/acme/issuers/cas?type=localca');
  const table = await screen.findByRole('table');
  // caLocal's name and its endpoint (subject common name) are both "Internal CA".
  expect(within(table).getAllByText('Internal CA')).toHaveLength(2);
  expect(within(table).queryByText(ca.name)).not.toBeInTheDocument();
  expect(within(table).queryByText('Vault PKI')).not.toBeInTheDocument();
  expect(within(table).getAllByRole('row')).toHaveLength(2); // header + Internal CA
});

it('kind switch keeps drafts', async () => {
  const { user } = renderRoute('/o/acme/issuers/cas?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  await user.click(await within(sheet).findByRole('button', { name: /^Custom/ }));
  const dirInput = within(sheet).getByLabelText('Directory URL');
  await user.clear(dirInput);
  await user.type(dirInput, 'https://ca.example.com/dir');
  await user.click(within(sheet).getByRole('radio', { name: 'Built-in CA' }));
  await user.click(within(sheet).getByRole('radio', { name: 'ACME' }));
  expect(within(sheet).getByLabelText('Directory URL')).toHaveValue('https://ca.example.com/dir');
});

it('localca create posts type and config', async () => {
  withSigners();
  const { user } = renderRoute('/o/acme/issuers/cas?edit=new&kind=localca');
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  await user.type(within(sheet).getByLabelText('Name'), 'Internal CA');
  await user.type(await within(sheet).findByLabelText('Common name'), 'Internal CA');
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  await waitFor(() => expect(posted).toBeDefined());
  expect(posted).toMatchObject({
    name: 'Internal CA',
    type: 'localca',
    config: { subject: { commonName: 'Internal CA' } },
  });
  expect(posted).not.toHaveProperty('preset');
});

it('import switch reveals PEM fields', async () => {
  withSigners();
  const { user } = renderRoute('/o/acme/issuers/cas?edit=new&kind=localca');
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  expect(await within(sheet).findByLabelText('Common name')).toBeInTheDocument();
  expect(within(sheet).queryByLabelText('Import: certificate chain')).not.toBeInTheDocument();
  await user.click(within(sheet).getByRole('switch', { name: 'Import existing CA' }));
  expect(within(sheet).queryByLabelText('Common name')).not.toBeInTheDocument();
  expect(within(sheet).getByLabelText('Import: certificate chain')).toBeInTheDocument();
  expect(within(sheet).getByLabelText('Import: private key')).toBeInTheDocument();
});

it('vaultpki without vault settings shows link', async () => {
  withSigners();
  // test/server.ts's default /settings/vault has no address.
  const { user } = renderRoute('/o/acme/issuers/cas?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  await user.click(within(sheet).getByRole('radio', { name: 'Vault PKI' }));
  expect(await within(sheet).findByText(/Vault is not configured/)).toBeInTheDocument();
  expect(within(sheet).getByRole('link', { name: /Settings/ })).toBeInTheDocument();
  expect(within(sheet).getByRole('button', { name: 'Save CA' })).toBeEnabled();
});

it('type locked on edit', async () => {
  cas = [caLocal];
  withSigners();
  renderRoute('/o/acme/issuers/cas?edit=ca-local-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit Internal CA' });
  expect(within(sheet).getByRole('radio', { name: 'ACME' })).toBeDisabled();
  expect(within(sheet).getByRole('radio', { name: 'Built-in CA' })).toBeDisabled();
  expect(within(sheet).getByRole('radio', { name: 'Vault PKI' })).toBeDisabled();
});

// Batch 1 review (Important): `initialDraft` used to seed the edit form with
// the full `ca.config` (including read-only `imported`/`issuingPem`/
// `retired`/`revokedCount`), which the signers[localca] schema's
// `additionalProperties: false` rejects — SchemaForm's Ajv `validate()`
// failed silently and Save did nothing. This exercises the real rendered
// form (not just `caBody.test.ts`'s pure `toCaInput`), so it actually
// reaches that validation.
it('localca edit saves', async () => {
  cas = [caLocal];
  withSigners();
  const { user } = renderRoute('/o/acme/issuers/cas?edit=ca-local-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit Internal CA' });
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  await waitFor(() => expect(put).toBeDefined());
  expect(put).toEqual({ name: 'Internal CA', type: 'localca', config: { maxLeafDays: 397, crl: true } });
});

it('import key not cached', async () => {
  withSigners();
  server.use(
    http.post(url('/orgs/org-1/cas'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json({ ...caLocal, id: 'ca-9', name: (posted as CAInput).name }, { status: 201 });
    }),
  );
  const { user, queryClient } = renderRoute('/o/acme/issuers/cas?edit=new&kind=localca');
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  await user.type(within(sheet).getByLabelText('Name'), 'Imported CA');
  await user.click(within(sheet).getByRole('switch', { name: 'Import existing CA' }));
  await user.type(within(sheet).getByLabelText('Import: certificate chain'), '-----BEGIN CERTIFICATE-----');
  await user.type(within(sheet).getByLabelText('Import: private key'), '-----BEGIN PRIVATE KEY-----');
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(queryClient.getMutationCache().getAll()).toEqual([]);
  expect(JSON.stringify(queryClient.getQueryCache().getAll())).not.toContain('BEGIN PRIVATE KEY');
});

it('private row opens view', async () => {
  cas = [caLocal];
  const { router, user } = renderRoute('/o/acme/issuers/cas');
  const nameCells = await screen.findAllByText('Internal CA');
  await user.click(nameCells[0]!);
  await waitFor(() => expect(router.state.location.search).toMatchObject({ view: 'ca-local-1' }));
  expect(router.state.location.search).not.toHaveProperty('edit');
});

it('read-only user sees disabled Save', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: 'org-1' }]))));
  renderRoute('/o/acme/issuers/cas?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  expect(within(sheet).getByRole('button', { name: 'Save CA' })).toBeDisabled();
});
