import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import type { CA } from '@/api/types';
import { help } from '@/lib/help';
import { server } from '@/test/server';
import { authHandlers, ca, caLocal, caLocalImported, caLocalNeverRotated, caVaultPki, meWith, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let cas: CA[];
let rotated: string | undefined;
// Same convention as certificates/detail/download.test.tsx: stub the blob
// URL/anchor machinery `saveBlob` drives, instead of spying its module.
let clicked: { download: string } | undefined;
let capturedBlob: Blob | undefined;
beforeEach(() => {
  cas = [];
  rotated = undefined;
  clicked = undefined;
  capturedBlob = undefined;
  URL.createObjectURL = vi.fn((b: Blob) => {
    capturedBlob = b;
    return 'blob:test';
  });
  URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    clicked = { download: this.download };
  });
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json(cas)),
    http.post(url('/orgs/org-1/cas/:id/rotate'), ({ params }) => {
      rotated = String(params.id);
      return HttpResponse.json({ ...caLocal, id: rotated });
    }),
  );
});

it('localca details and crl copy', async () => {
  cas = [caLocal];
  const { user } = renderRoute('/o/acme/issuers/cas?view=ca-local-1');
  const sheet = await screen.findByRole('dialog', { name: 'Internal CA' });
  expect(within(sheet).getByText('Built-in CA')).toBeInTheDocument();
  expect(within(sheet).getByText('CN=Internal CA, O=Acme, C=US')).toBeInTheDocument();
  expect(within(sheet).getByText('397')).toBeInTheDocument(); // max leaf days
  expect(within(sheet).getByText('1')).toBeInTheDocument(); // revokedCount
  await within(sheet).findByText('https://certs.example.com/crl/ca-local-1.crl');
  await user.click(within(sheet).getByRole('button', { name: 'Copy CRL URL' }));
  expect(await navigator.clipboard.readText()).toBe('https://certs.example.com/crl/ca-local-1.crl');
});

it('never-rotated localca has no retired issuers section', async () => {
  cas = [caLocalNeverRotated];
  renderRoute('/o/acme/issuers/cas?view=ca-local-3');
  const sheet = await screen.findByRole('dialog', { name: 'Never Rotated CA' });
  expect(within(sheet).queryByText('Retired issuers')).not.toBeInTheDocument();
});

it('validity bar for both kinds', async () => {
  cas = [caLocal, caVaultPki];
  const first = renderRoute('/o/acme/issuers/cas?view=ca-local-1');
  const localSheet = await screen.findByRole('dialog', { name: 'Internal CA' });
  expect(within(localSheet).getByRole('img')).toHaveAccessibleName(new RegExp(caLocal.notBefore!.slice(0, 4)));
  first.unmount();

  renderRoute('/o/acme/issuers/cas?view=ca-vault-1');
  const vaultSheet = await screen.findByRole('dialog', { name: 'Vault PKI' });
  expect(within(vaultSheet).getByRole('img')).toHaveAccessibleName(new RegExp(caVaultPki.notBefore!.slice(0, 4)));
});

it('trust bundle download', async () => {
  cas = [caLocal];
  const { user } = renderRoute('/o/acme/issuers/cas?view=ca-local-1');
  const sheet = await screen.findByRole('dialog', { name: 'Internal CA' });
  await user.click(within(sheet).getByRole('button', { name: /Download/ }));
  expect(clicked?.download).toBe('internal-ca-ca.pem');
  await expect(capturedBlob!.text()).resolves.toBe(caLocal.trustBundlePem);
});

it('vault trust download', async () => {
  cas = [caVaultPki];
  const { user } = renderRoute('/o/acme/issuers/cas?view=ca-vault-1');
  const sheet = await screen.findByRole('dialog', { name: 'Vault PKI' });
  await user.click(within(sheet).getByRole('button', { name: /Download/ }));
  expect(clicked?.download).toBe('vault-pki-ca.pem');
  await expect(capturedBlob!.text()).resolves.toBe(caVaultPki.trustBundlePem);
});

it('retired chip copies its crl url', async () => {
  cas = [caLocal];
  const { user } = renderRoute('/o/acme/issuers/cas?view=ca-local-1');
  const sheet = await screen.findByRole('dialog', { name: 'Internal CA' });
  await user.click(within(sheet).getByRole('button', { name: /aa11bb22/ }));
  expect(await navigator.clipboard.readText()).toBe('https://certs.example.com/crl/ca-local-1/aa11bb22.crl');
  await screen.findByText('CRL URL copied');
});

it('retired chip without crl url disabled', async () => {
  cas = [caLocal];
  const { user } = renderRoute('/o/acme/issuers/cas?view=ca-local-1');
  const sheet = await screen.findByRole('dialog', { name: 'Internal CA' });
  const chip = within(sheet).getByRole('button', { name: /cc33dd44/ });
  expect(chip).toBeDisabled();
  await user.hover(chip);
  const tooltip = await screen.findByRole('tooltip');
  expect(tooltip).toHaveTextContent(help['ca.retiredNoCrl'].text);
  expect(within(tooltip).getByRole('link', { name: 'Learn more' })).toBeInTheDocument();
});

it('rotate confirms and posts', async () => {
  cas = [caLocal];
  const { user } = renderRoute('/o/acme/issuers/cas?view=ca-local-1');
  const sheet = await screen.findByRole('dialog', { name: 'Internal CA' });
  await user.click(within(sheet).getByRole('button', { name: 'Rotate issuing certificate' }));
  const dialog = await screen.findByRole('dialog', { name: 'Rotate issuing certificate?' });
  await user.type(within(dialog).getByRole('textbox'), 'Rotate');
  await user.click(within(dialog).getByRole('button', { name: 'Rotate' }));
  await waitFor(() => expect(rotated).toBe('ca-local-1'));
});

it('imported cannot rotate', async () => {
  cas = [caLocalImported];
  const { user } = renderRoute('/o/acme/issuers/cas?view=ca-local-2');
  const sheet = await screen.findByRole('dialog', { name: 'Imported CA' });
  const rotateBtn = within(sheet).getByRole('button', { name: 'Rotate issuing certificate' });
  expect(rotateBtn).toBeDisabled();
  await user.hover(rotateBtn);
  const tooltip = await screen.findByRole('tooltip');
  expect(tooltip).toHaveTextContent(help['ca.rotateImported'].text);
  expect(within(tooltip).getByRole('link', { name: 'Learn more' })).toBeInTheDocument();
});

it('rotate needs cas:write', async () => {
  cas = [caLocal];
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: 'org-1' }]))));
  renderRoute('/o/acme/issuers/cas?view=ca-local-1');
  const sheet = await screen.findByRole('dialog', { name: 'Internal CA' });
  expect(within(sheet).getByRole('button', { name: 'Rotate issuing certificate' })).toBeDisabled();
  expect(within(sheet).getByRole('button', { name: 'Edit' })).toBeDisabled();
});

it('crl missing base url', async () => {
  cas = [{ ...caLocal, crlUrl: undefined }];
  renderRoute('/o/acme/issuers/cas?view=ca-local-1');
  const sheet = await screen.findByRole('dialog', { name: 'Internal CA' });
  expect(within(sheet).getByText(/Set the base URL/)).toBeInTheDocument();
  expect(within(sheet).getByRole('link', { name: /Settings/ })).toBeInTheDocument();
});

it('unknown id shows not found', async () => {
  cas = [ca];
  const { router, user } = renderRoute('/o/acme/issuers/cas?view=nope');
  const dialog = await screen.findByRole('dialog', { name: 'CA not found' });
  await user.click(within(dialog).getByRole('button', { name: 'Back to CAs' }));
  await waitFor(() => expect(router.state.location.search).toEqual({}));
});

it('opens the private CA detail from the keyboard on its focused row', async () => {
  cas = [caLocal];
  const { user } = renderRoute('/o/acme/issuers/cas');
  const row = (await screen.findByText('Internal CA')).closest('tr')!;
  row.focus();
  await user.keyboard('{Enter}');
  expect(await screen.findByRole('dialog', { name: 'Internal CA' })).toBeInTheDocument();
});
