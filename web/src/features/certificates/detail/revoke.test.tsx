import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import type { CA, CertificateVersion } from '@/api/types';
import { can } from '@/lib/permissions';
import { server } from '@/test/server';
import { ca, caLocal, iso, makeCert, makeVersion, meWith, org, problem, url } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { VersionsTab } from './VersionsTab';

const cert = makeCert({ effective: { caId: { value: caLocal.id, source: 'cert' } } });
const serial = cert.currentVersion!.serial;

function setup(opts: { versions?: CertificateVersion[]; cas?: CA[]; canRevoke?: boolean; certOverride?: typeof cert } = {}) {
  const { versions = [cert.currentVersion!], cas = [caLocal], canRevoke = true, certOverride = cert } = opts;
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/versions'), () => HttpResponse.json(versions)),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json(cas)),
  );
  const onDownload = vi.fn();
  const onRenew = vi.fn();
  const utils = renderUI(<VersionsTab cert={certOverride} orgId="org-1" onDownload={onDownload} onRenew={onRenew} canRevoke={canRevoke} />);
  return { ...utils, onDownload, onRenew };
}

beforeEach(() => {
  URL.createObjectURL = vi.fn(() => 'blob:test');
  URL.revokeObjectURL = vi.fn();
});

it('private issued version shows revoke', async () => {
  setup();
  expect(await screen.findByRole('button', { name: `Revoke version ${serial}` })).toBeEnabled();
});

it('acme has no revoke', async () => {
  const acmeCert = makeCert({ effective: { caId: { value: ca.id, source: 'cert' } } });
  setup({ cas: [ca], certOverride: acmeCert });
  await screen.findByRole('button', { name: `Download version ${serial}` });
  expect(screen.queryByRole('button', { name: /Revoke version/ })).not.toBeInTheDocument();
});

it('uploaded version has no revoke', async () => {
  const uploaded = makeVersion({ source: 'uploaded' });
  setup({ versions: [uploaded] });
  await screen.findByRole('button', { name: `Download version ${uploaded.serial}` });
  expect(screen.queryByRole('button', { name: /Revoke version/ })).not.toBeInTheDocument();
});

it('revoke posts reason', async () => {
  let body: unknown;
  server.use(
    http.post(url('/orgs/org-1/certificates/c-1/versions/v-1/revoke'), async ({ request }) => {
      body = await request.json();
      return HttpResponse.json({ ...cert.currentVersion!, revokedAt: iso(0) });
    }),
  );
  const { user } = setup();
  await user.click(await screen.findByRole('button', { name: `Revoke version ${serial}` }));
  const dialog = await screen.findByRole('dialog', { name: `Revoke version ${serial}?` });
  await user.click(within(dialog).getByRole('combobox', { name: 'Reason' }));
  await user.click(screen.getByRole('option', { name: 'Key compromise' }));
  await user.type(within(dialog).getByLabelText(/Type/), 'Revoke');
  await user.click(within(dialog).getByRole('button', { name: 'Revoke' }));
  await waitFor(() => expect(body).toEqual({ reason: 'keyCompromise' }));
});

it('revoked chip replaces action', async () => {
  const revoked = makeVersion({ revokedAt: iso(-1) });
  setup({ versions: [revoked] });
  expect(await screen.findByText('Revoked')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Revoke version/ })).not.toBeInTheDocument();
});

it('409 toasts already revoked', async () => {
  server.use(http.post(url('/orgs/org-1/certificates/c-1/versions/v-1/revoke'), () => problem(409, 'already revoked')));
  const { user } = setup();
  await user.click(await screen.findByRole('button', { name: `Revoke version ${serial}` }));
  const dialog = await screen.findByRole('dialog', { name: `Revoke version ${serial}?` });
  await user.type(within(dialog).getByLabelText(/Type/), 'Revoke');
  await user.click(within(dialog).getByRole('button', { name: 'Revoke' }));
  expect(await screen.findByText('Already revoked')).toBeInTheDocument();
});

it('needs certs:issue', async () => {
  const canRevoke = can(meWith([{ role: 'viewer', orgId: org.id }]), 'certs:issue', org.id);
  setup({ canRevoke });
  expect(await screen.findByRole('button', { name: `Revoke version ${serial}` })).toBeDisabled();
});
