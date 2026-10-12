import { readFileSync } from 'node:fs';
import path from 'node:path';
import { useState } from 'react';
import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import type { RJSFSchema } from '@rjsf/utils';
import { expect, it } from 'vitest';
import type { TlsPeekRequest } from '@/api/types';
import { SchemaForm } from '@/forms/SchemaForm';
import type { CaBundleScope } from './CaBundleInput';
import { ca, caLocal, url } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { server } from '@/test/server';

const fixtures = path.resolve(import.meta.dirname, '../../e2e/fixtures');
const PEM = readFileSync(path.join(fixtures, 'ca.pem'), 'utf8');
const DER = readFileSync(path.join(fixtures, 'ca.der'));
const FP = 'E3:C1:98:FD:06:FA:9C:E9:DE:CE:2B:72:6B:97:5C:AA:6A:05:DF:5A:E0:61:28:60:36:E5:21:25:37:B0:5F:BF';

const schema = {
  type: 'object',
  properties: {
    url: { type: 'string', format: 'uri', title: 'API URL' },
    caPem: { type: 'string', format: 'pem-bundle', title: 'CA certificate' },
  },
} as RJSFSchema;

const full: CaBundleScope = { orgId: 'org-1', canPeek: true, canReadCas: true };

function Harness({ scope = full, initial = {} }: { scope?: CaBundleScope; initial?: Record<string, unknown> }) {
  const [v, setV] = useState<Record<string, unknown>>(initial);
  return (
    <>
      <SchemaForm schema={schema} value={v} onChange={setV} formContext={{ caBundle: scope }} />
      <output data-testid="value">{String(v.caPem ?? '')}</output>
    </>
  );
}

const value = () => screen.getByTestId('value').textContent;
const box = () => screen.getByRole('textbox', { name: /CA certificate/ });

it('keeps newlines on paste and summarizes the parsed certificate', async () => {
  const { user } = renderUI(<Harness />);
  await user.click(box());
  await user.paste(PEM);
  expect(value()).toBe(PEM);
  expect(screen.getByText('1 certificate')).toBeInTheDocument();
  expect(screen.getByText('CertForge Test Root')).toBeInTheDocument();
  expect(screen.getByText(/^expires /)).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('flags content that is not PEM', async () => {
  const { user } = renderUI(<Harness />);
  await user.type(box(), 'not a certificate');
  expect(screen.getByRole('alert')).toHaveTextContent('Not PEM');
});

it('appends an uploaded PEM file as-is, skipping a certificate already present', async () => {
  const { user } = renderUI(<Harness initial={{ caPem: PEM }} />);
  await user.upload(screen.getByLabelText('Upload CA certificate'), new File([PEM], 'ca.pem', { type: 'application/x-pem-file' }));
  expect(value()).toBe(PEM);
  await user.upload(screen.getByLabelText('Upload CA certificate'), new File([caLocal.trustBundlePem], 'other.crt'));
  expect(value()).toBe(PEM + caLocal.trustBundlePem);
});

it('converts an uploaded DER certificate to PEM in the browser', async () => {
  const { user } = renderUI(<Harness />);
  await user.upload(screen.getByLabelText('Upload CA certificate'), new File([DER], 'ca.der'));
  expect(value()).toBe(PEM);
  await user.upload(screen.getByLabelText('Upload CA certificate'), new File(['garbage'], 'x.cer'));
  expect(screen.getByRole('alert')).toHaveTextContent('x.cer is not a PEM or DER certificate.');
});

it('fetches the chain from the form URL, suggests the topmost CA and adds the picks', async () => {
  let sent: TlsPeekRequest | undefined;
  const leaf = { subject: 'CN=fw.example.net', issuer: 'CN=CertForge Test Root,O=CertForge Test', notBefore: '2026-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z', sha256: 'AA:BB', isCa: false, selfSigned: false, pem: '-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n' };
  const root = { subject: 'CN=CertForge Test Root,O=CertForge Test', issuer: 'CN=CertForge Test Root,O=CertForge Test', notBefore: '2026-01-01T00:00:00Z', notAfter: '2126-01-01T00:00:00Z', sha256: FP, isCa: true, selfSigned: true, pem: PEM };
  server.use(
    http.post(url('/orgs/org-1/tls/peek'), async ({ request }) => {
      sent = (await request.json()) as TlsPeekRequest;
      return HttpResponse.json({ ok: true, verified: false, chain: [leaf, root] });
    }),
  );
  const { user } = renderUI(<Harness initial={{ url: 'https://fw.example.net/api/v2' }} />);
  await user.click(screen.getByRole('button', { name: 'Fetch from server' }));
  const dialog = await screen.findByRole('dialog', { name: /Fetch from server/ });
  expect(within(dialog).getByRole('textbox', { name: 'Server' })).toHaveValue('https://fw.example.net/api/v2');
  await user.click(within(dialog).getByRole('button', { name: 'Fetch' }));
  const rootItem = await within(dialog).findByRole('button', { name: /CertForge Test Root.*CA.*Self-signed/ });
  expect(sent).toEqual({ url: 'https://fw.example.net/api/v2' });
  expect(within(dialog).getByText('Not verified by system roots.')).toBeInTheDocument();
  expect(within(dialog).getByText(`SHA-256 ${FP}`)).toBeInTheDocument();
  expect(rootItem).toHaveAttribute('aria-pressed', 'true');
  const leafItem = within(dialog).getByRole('button', { name: /fw\.example\.net/ });
  expect(leafItem).toHaveAttribute('aria-pressed', 'false');
  await user.click(leafItem);
  await user.click(within(dialog).getByRole('button', { name: 'Add 2 certificates' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(value()).toBe(leaf.pem + PEM);
});

it('shows a failed peek inline', async () => {
  server.use(http.post(url('/orgs/org-1/tls/peek'), () => HttpResponse.json({ ok: false, error: 'connection refused', chain: [], verified: false })));
  const { user } = renderUI(<Harness />);
  await user.click(screen.getByRole('button', { name: 'Fetch from server' }));
  const dialog = await screen.findByRole('dialog');
  await user.type(within(dialog).getByRole('textbox', { name: 'Server' }), 'fw.lan:443');
  await user.click(within(dialog).getByRole('button', { name: 'Fetch' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('connection refused');
  expect(within(dialog).getByRole('button', { name: 'Add certificate' })).toBeDisabled();
});

it('inserts a copy of a saved CA bundle, listing only CAs that have one', async () => {
  server.use(http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca, caLocal])));
  const { user } = renderUI(<Harness />);
  await user.click(await screen.findByRole('combobox', { name: 'CA certificate from saved CA' }));
  expect(screen.queryByRole('option', { name: ca.name })).not.toBeInTheDocument();
  await user.click(screen.getByRole('option', { name: caLocal.name }));
  expect(value()).toBe(caLocal.trustBundlePem);
});

it('disables Fetch behind a permission tooltip without delivery:write or cas:write', async () => {
  const { user } = renderUI(<Harness scope={{ orgId: 'org-1', canPeek: false, canReadCas: false }} />);
  const fetch = screen.getByRole('button', { name: 'Fetch from server' });
  expect(fetch).toBeDisabled();
  await user.hover(fetch.parentElement!);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the delivery:write or cas:write permission');
  expect(screen.queryByRole('combobox', { name: /from saved CA/ })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Upload' })).toBeEnabled();
});
