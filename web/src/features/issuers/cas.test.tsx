import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import type { CA, CAInput } from '@/api/types';
import { UNCHANGED } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, ca, presets, problem, url } from '@/test/fixtures';
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
    http.post(url('/orgs/org-1/cas'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json({ ...(posted as object), id: 'ca-9' }, { status: 201 });
    }),
    http.put(url('/orgs/org-1/cas/:id'), async ({ request }) => {
      put = (await request.json()) as CAInput;
      return HttpResponse.json(put);
    }),
    http.delete(url('/orgs/org-1/cas/:id'), () => problem(409, 'CA is used by 2 certificates')),
  );
});

it('adds a CA from a preset card', async () => {
  const { router, user } = renderRoute('/o/acme/issuers/cas');
  await user.click(await screen.findByRole('button', { name: 'Add CA' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add certificate authority' });
  await user.click(await within(sheet).findByRole('button', { name: /Let's Encrypt staging/ }));
  expect(within(sheet).getByLabelText('Name')).toHaveValue("Let's Encrypt staging");
  await user.click(within(sheet).getByRole('button', { name: 'Save CA' }));
  await waitFor(() =>
    expect(posted).toEqual({ name: "Let's Encrypt staging", preset: 'letsencrypt-staging', directoryUrl: presets[1]!.directoryUrl, resolvers: [] }),
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
