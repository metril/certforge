import { http, HttpResponse } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeCert, meWith, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// A successful upload always navigates to the new certificate's overview
// tab, which fires a batch of its own queries (header, coverage panel,
// attempts, manual-dns) regardless of whether a given test asserts on the
// navigation — mirroring wizard.test.tsx's Task 16 note, these are stubbed
// unconditionally so a background fetch settling after a test ends never
// logs an "unhandled request" console.error attributed to the next test.
beforeEach(() => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/certificates/c-new'), () => HttpResponse.json(makeCert({ id: 'c-new', name: 'legacy-api' }))),
    http.get(url('/orgs/org-1/certificates/c-new/attempts'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/certificates/c-new/manual-dns'), () => problem(404, 'none')),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/clients'), () => HttpResponse.json({ items: [], nextCursor: null })),
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json({ builtin: {} })),
  );
});

it('PEM upload: posts certificatePem and privateKeyPem, then lands on the detail page', async () => {
  let body: unknown;
  server.use(
    http.post(url('/orgs/org-1/certificates/upload'), async ({ request }) => {
      body = await request.json();
      return HttpResponse.json(makeCert({ id: 'c-new', name: 'legacy-api' }), { status: 201 });
    }),
  );
  const { user, router } = renderRoute('/o/acme/certificates/upload');
  await user.type(await screen.findByLabelText('Name'), 'legacy-api');
  await user.type(screen.getByLabelText('Certificate'), 'CERT-DATA');
  await user.type(screen.getByLabelText('Private key'), 'KEY-DATA');
  await user.click(screen.getByRole('button', { name: 'Upload' }));
  await waitFor(() => expect(body).toEqual({ name: 'legacy-api', certificatePem: 'CERT-DATA', privateKeyPem: 'KEY-DATA' }));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/certificates/c-new/overview'));
  // Lets the detail page's own queries settle before the test ends, so none
  // of them land after this file's handlers reset for the next test.
  await screen.findByRole('navigation', { name: 'Breadcrumb' });
});

it('PEM without key omits privateKeyPem', async () => {
  let body: unknown;
  server.use(
    http.post(url('/orgs/org-1/certificates/upload'), async ({ request }) => {
      body = await request.json();
      return HttpResponse.json(makeCert({ id: 'c-new', name: 'legacy-api' }), { status: 201 });
    }),
  );
  const { user } = renderRoute('/o/acme/certificates/upload');
  await user.type(await screen.findByLabelText('Name'), 'legacy-api');
  await user.type(screen.getByLabelText('Certificate'), 'CERT-DATA');
  await user.click(screen.getByRole('button', { name: 'Upload' }));
  await waitFor(() => expect(body).toEqual({ name: 'legacy-api', certificatePem: 'CERT-DATA' }));
});

it('P12 upload: sends the base64 of the uploaded bytes plus the password', async () => {
  let body: { pkcs12Base64?: string; password?: string; name?: string } | undefined;
  server.use(
    http.post(url('/orgs/org-1/certificates/upload'), async ({ request }) => {
      body = (await request.json()) as typeof body;
      return HttpResponse.json(makeCert({ id: 'c-new', name: 'legacy-api' }), { status: 201 });
    }),
  );
  const { user } = renderRoute('/o/acme/certificates/upload');
  await user.type(await screen.findByLabelText('Name'), 'legacy-api');
  await user.click(screen.getByRole('radio', { name: 'PKCS#12' }));
  const bytes = new Uint8Array([1, 2, 3]);
  const file = new File([bytes], 'bundle.p12', { type: 'application/x-pkcs12' });
  await user.upload(screen.getByLabelText('File'), file);
  await user.type(screen.getByLabelText('Password'), 's3cret');
  // Fix round 1 (review, Minor): a password manager must not offer to
  // generate/save a password for an existing PKCS#12 file.
  expect(screen.getByLabelText('Password')).toHaveAttribute('autocomplete', 'off');
  await user.click(screen.getByRole('button', { name: 'Upload' }));
  await waitFor(() => expect(body?.pkcs12Base64).toBe(btoa(String.fromCharCode(...bytes))));
  expect(body?.password).toBe('s3cret');
  expect(body?.name).toBe('legacy-api');
});

it('p12 too large: shows the error and sends no request', async () => {
  let posted = false;
  server.use(http.post(url('/orgs/org-1/certificates/upload'), () => ((posted = true), new HttpResponse(null, { status: 201 }))));
  const { user } = renderRoute('/o/acme/certificates/upload');
  await user.type(await screen.findByLabelText('Name'), 'legacy-api');
  await user.click(screen.getByRole('radio', { name: 'PKCS#12' }));
  const big = new File([new Uint8Array(800 * 1024)], 'big.p12');
  await user.upload(screen.getByLabelText('File'), big);
  expect(await screen.findByText('Larger than 768 KiB.')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Upload' })).toBeDisabled();
  expect(posted).toBe(false);
});

// Fix round 1 (review, Minor): once a file is chosen, the File field swaps
// its Input for a name/size/Remove row — that row must keep the field's id
// so the Label stays associated with it and the too-large/422 error's
// aria-describedby still has a target to describe.
it('keeps the File field labelled and described once a file is chosen', async () => {
  const { user } = renderRoute('/o/acme/certificates/upload');
  await user.type(await screen.findByLabelText('Name'), 'legacy-api');
  await user.click(screen.getByRole('radio', { name: 'PKCS#12' }));
  const big = new File([new Uint8Array(800 * 1024)], 'big.p12');
  await user.upload(screen.getByLabelText('File'), big);
  expect(screen.getByLabelText('File')).toHaveAccessibleDescription('Larger than 768 KiB.');
});

// Fix round 1 (review, Important): `ready` only checked the certificate
// material, not the Name field — Upload stayed enabled with a blank Name
// and `submit` silently no-opped (its own `if (!name.trim() ...) return`).
it('Upload stays disabled until Name is filled', async () => {
  const { user } = renderRoute('/o/acme/certificates/upload');
  await user.type(await screen.findByLabelText('Certificate'), 'CERT-DATA');
  expect(screen.getByRole('button', { name: 'Upload' })).toBeDisabled();
  await user.type(screen.getByLabelText('Name'), 'legacy-api');
  expect(screen.getByRole('button', { name: 'Upload' })).toBeEnabled();
});

it('422 maps to field: Invalid privateKeyPem shows under Private key', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/upload'), () => problem(422, "Doesn't match the certificate.", {}, 'Invalid privateKeyPem')));
  const { user } = renderRoute('/o/acme/certificates/upload');
  await user.type(await screen.findByLabelText('Name'), 'legacy-api');
  await user.type(screen.getByLabelText('Certificate'), 'CERT-DATA');
  await user.type(screen.getByLabelText('Private key'), 'KEY-DATA');
  await user.click(screen.getByRole('button', { name: 'Upload' }));
  expect(await screen.findByText("Doesn't match the certificate.")).toBeInTheDocument();
  const keyField = screen.getByLabelText('Private key');
  expect(keyField).toHaveAccessibleDescription(expect.stringContaining("Doesn't match the certificate."));
});

it('409 goes under Name', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/upload'), () => problem(409, 'A certificate named legacy-api already exists.')));
  const { user } = renderRoute('/o/acme/certificates/upload');
  await user.type(await screen.findByLabelText('Name'), 'legacy-api');
  await user.type(screen.getByLabelText('Certificate'), 'CERT-DATA');
  await user.click(screen.getByRole('button', { name: 'Upload' }));
  expect(await screen.findByText('A certificate named legacy-api already exists.')).toBeInTheDocument();
  const nameField = screen.getByLabelText('Name');
  expect(nameField).toHaveAccessibleDescription(expect.stringContaining('already exists'));
});

it('viewer: fields and Upload are disabled', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: 'org-1' }]))));
  renderRoute('/o/acme/certificates/upload');
  expect(await screen.findByLabelText('Name')).toBeDisabled();
  expect(screen.getByLabelText('Certificate')).toBeDisabled();
  // Fix round 1 (review, Minor): the Format segmented control was the one
  // upload control a viewer could still operate.
  expect(screen.getByRole('radio', { name: 'PEM' })).toBeDisabled();
  expect(screen.getByRole('radio', { name: 'PKCS#12' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Upload' })).toBeDisabled();
});
