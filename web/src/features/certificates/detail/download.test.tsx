import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { makeCert, makeVersion, meWith, org, problem, url } from '@/test/fixtures';
import { can } from '@/lib/permissions';
import { renderUI } from '@/test/render';
import { DownloadSheet } from './DownloadSheet';
import type { CertificateVersion } from '@/api/types';

const cert = makeCert();

function setup(opts: { canExportKey?: boolean; versions?: CertificateVersion[] } = {}) {
  const { canExportKey = true, versions = [cert.currentVersion!] } = opts;
  server.use(http.get(url('/orgs/org-1/certificates/c-1/versions'), () => HttpResponse.json(versions)));
  const onOpenChange = vi.fn();
  const utils = renderUI(<DownloadSheet orgId="org-1" cert={cert} canExportKey={canExportKey} onOpenChange={onOpenChange} />);
  return { ...utils, onOpenChange };
}

beforeEach(() => {
  URL.createObjectURL = vi.fn(() => 'blob:test');
  URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
});

it('DER parts: fullchain and combined are absent, and Download sends format=der&parts=cert', async () => {
  let query: URLSearchParams | undefined;
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/versions/v-1/download'), ({ request }) => {
      query = new URL(request.url).searchParams;
      return new HttpResponse('DER bytes', {
        headers: { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="www.der"' },
      });
    }),
  );
  const { user } = setup();
  const sheet = await screen.findByRole('dialog', { name: 'Download' });
  await user.click(within(sheet).getByRole('radio', { name: 'DER' }));
  expect(within(sheet).queryByRole('button', { name: 'fullchain' })).not.toBeInTheDocument();
  expect(within(sheet).queryByRole('button', { name: 'combined' })).not.toBeInTheDocument();
  await user.click(within(sheet).getByRole('button', { name: 'Download DER' }));
  await waitFor(() => expect(query?.get('format')).toBe('der'));
  expect(query?.get('parts')).toBe('cert');
});

it('P12 generated password: 24 characters, Copy writes it to the clipboard, and Download sends it with modern encoding', async () => {
  let body: unknown;
  server.use(
    http.post(url('/orgs/org-1/certificates/c-1/versions/v-1/export'), async ({ request }) => {
      body = await request.json();
      return new HttpResponse('PK', { headers: { 'Content-Type': 'application/x-pkcs12', 'Content-Disposition': 'attachment; filename="www.p12"' } });
    }),
  );
  const { user } = setup();
  const sheet = await screen.findByRole('dialog', { name: 'Download' });
  await user.click(within(sheet).getByRole('radio', { name: 'PKCS#12' }));
  const pwField = within(sheet).getByLabelText('Generated password') as HTMLInputElement;
  expect(pwField.value).toHaveLength(24);
  await user.click(within(sheet).getByRole('button', { name: 'Copy password' }));
  expect(await navigator.clipboard.readText()).toBe(pwField.value);
  await user.click(within(sheet).getByRole('button', { name: 'Download PKCS#12' }));
  await waitFor(() => expect(body).toEqual({ format: 'p12', password: pwField.value, encoding: 'modern' }));
});

it('use my own password: switching to JKS with a short password disables Download and shows the length error', async () => {
  const { user } = setup();
  const sheet = await screen.findByRole('dialog', { name: 'Download' });
  await user.click(within(sheet).getByRole('radio', { name: 'PKCS#12' }));
  await user.click(within(sheet).getByRole('switch', { name: 'Use my own password' }));
  await user.type(within(sheet).getByLabelText('Password'), 'abc');
  await user.click(within(sheet).getByRole('radio', { name: 'JKS' }));
  expect(await within(sheet).findByText('At least 6 characters.')).toBeInTheDocument();
  expect(within(sheet).getByRole('button', { name: 'Download JKS' })).toBeDisabled();
});

it('legacy encoding and alias: the body carries encoding:legacy, and JKS sends alias only when non-empty', async () => {
  let p12Body: { encoding?: string } | undefined;
  server.use(
    http.post(url('/orgs/org-1/certificates/c-1/versions/v-1/export'), async ({ request }) => {
      p12Body = (await request.json()) as { encoding?: string };
      return new HttpResponse('PK', { headers: { 'Content-Type': 'application/x-pkcs12', 'Content-Disposition': 'attachment; filename="www.p12"' } });
    }),
  );
  const { user } = setup();
  const sheet = await screen.findByRole('dialog', { name: 'Download' });
  await user.click(within(sheet).getByRole('radio', { name: 'PKCS#12' }));
  await user.click(within(sheet).getByRole('radio', { name: 'Legacy' }));
  await user.click(within(sheet).getByRole('button', { name: 'Download PKCS#12' }));
  await waitFor(() => expect(p12Body?.encoding).toBe('legacy'));

  let jksBody: { alias?: string } | undefined;
  server.use(
    http.post(url('/orgs/org-1/certificates/c-1/versions/v-1/export'), async ({ request }) => {
      jksBody = (await request.json()) as { alias?: string };
      return new HttpResponse('PK', { headers: { 'Content-Type': 'application/x-java-keystore', 'Content-Disposition': 'attachment; filename="www.jks"' } });
    }),
  );
  await user.click(within(sheet).getByRole('radio', { name: 'JKS' }));
  await user.click(within(sheet).getByRole('button', { name: 'Download JKS' }));
  await waitFor(() => expect(jksBody).not.toHaveProperty('alias'));

  await user.type(within(sheet).getByLabelText('Alias'), 'tomcat');
  await user.click(within(sheet).getByRole('button', { name: 'Download JKS' }));
  await waitFor(() => expect(jksBody?.alias).toBe('tomcat'));
});

it('no keys:export: the P12 and JKS segments are disabled', async () => {
  const canExportKey = can(meWith([{ role: 'operator', orgId: org.id }]), 'keys:export', org.id);
  setup({ canExportKey });
  const sheet = await screen.findByRole('dialog', { name: 'Download' });
  expect(within(sheet).getByRole('radio', { name: 'PKCS#12' })).toBeDisabled();
  expect(within(sheet).getByRole('radio', { name: 'JKS' })).toBeDisabled();
});

it('keyless version: hasKey false disables key, combined, P12 and JKS', async () => {
  setup({ versions: [makeVersion({ hasKey: false })] });
  const sheet = await screen.findByRole('dialog', { name: 'Download' });
  await waitFor(() => expect(within(sheet).getByRole('button', { name: 'key' })).toBeDisabled());
  expect(within(sheet).getByRole('button', { name: 'combined' })).toBeDisabled();
  expect(within(sheet).getByRole('radio', { name: 'PKCS#12' })).toBeDisabled();
  expect(within(sheet).getByRole('radio', { name: 'JKS' })).toBeDisabled();
});

it('export password stays out of caches, the mutation cache, and localStorage', async () => {
  let capturedPassword: string | undefined;
  server.use(
    http.post(url('/orgs/org-1/certificates/c-1/versions/v-1/export'), async ({ request }) => {
      capturedPassword = ((await request.json()) as { password: string }).password;
      return new HttpResponse('PK', { headers: { 'Content-Type': 'application/x-pkcs12', 'Content-Disposition': 'attachment; filename="www.p12"' } });
    }),
  );
  const { user, queryClient, onOpenChange } = setup();
  const sheet = await screen.findByRole('dialog', { name: 'Download' });
  await user.click(within(sheet).getByRole('radio', { name: 'PKCS#12' }));
  await user.click(within(sheet).getByRole('button', { name: 'Download PKCS#12' }));
  await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
  expect(capturedPassword).toHaveLength(24);
  const cacheStr = JSON.stringify(queryClient.getQueryCache().getAll().map((q) => q.state.data));
  expect(cacheStr).not.toContain(capturedPassword);
  const mutationStr = JSON.stringify(queryClient.getMutationCache().getAll().map((m) => m.state));
  expect(mutationStr).not.toContain(capturedPassword);
  for (let i = 0; i < localStorage.length; i++) {
    expect(localStorage.getItem(localStorage.key(i)!)).not.toContain(capturedPassword);
  }
});

it('server 422 on password shows inline', async () => {
  server.use(
    http.post(url('/orgs/org-1/certificates/c-1/versions/v-1/export'), () =>
      problem(422, 'password must be at least 6 characters for jks', {}, 'Invalid password'),
    ),
  );
  const { user } = setup();
  const sheet = await screen.findByRole('dialog', { name: 'Download' });
  await user.click(within(sheet).getByRole('radio', { name: 'JKS' }));
  await user.click(within(sheet).getByRole('button', { name: 'Download JKS' }));
  expect(await within(sheet).findByText('password must be at least 6 characters for jks')).toBeInTheDocument();
});
