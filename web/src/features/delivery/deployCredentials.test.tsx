import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import type { DeployCredential } from '@/api/types';
import { UNCHANGED } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, deployCredentialKinds, makeDeployCredential, makeTarget, meWith, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let creds: DeployCredential[];
let posted: unknown;
let put: unknown;
let deleted: string | undefined;
let revealed: unknown;

beforeEach(() => {
  creds = [];
  posted = put = deleted = revealed = undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [], deployCredentials: deployCredentialKinds, notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-credentials'), () => HttpResponse.json(creds)),
    http.post(url('/orgs/org-1/deploy-credentials'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json(makeDeployCredential({ id: 'dc-9' }), { status: 201 });
    }),
    http.put(url('/orgs/org-1/deploy-credentials/:id'), async ({ request }) => {
      put = await request.json();
      return HttpResponse.json(makeDeployCredential());
    }),
    http.delete(url('/orgs/org-1/deploy-credentials/:id'), ({ params }) => {
      deleted = String(params.id);
      return new HttpResponse(null, { status: 204 });
    }),
    http.post(url('/orgs/org-1/deploy-credentials/:id/reveal'), async ({ request }) => {
      revealed = await request.json();
      return HttpResponse.json({ field: 'privateKey', value: 'PEM-PLAIN' });
    }),
  );
});

it('shows the Credentials tab and an empty state', async () => {
  renderRoute('/o/acme/delivery/credentials');
  expect(await screen.findByText('No saved credentials yet.')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Credentials' })).toBeInTheDocument();
});

it('adds a password credential through the kind select', async () => {
  const { user } = renderRoute('/o/acme/delivery/credentials');
  await user.click(await screen.findByRole('button', { name: 'Add credential' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add credential' });
  await user.type(within(sheet).getByLabelText('Name'), 'router admin');
  await user.click(within(sheet).getByRole('radio', { name: 'Password' }));
  await user.type(within(sheet).getByLabelText('Username'), 'admin');
  await user.type(within(sheet).getByLabelText('Password'), 'pw');
  await user.click(within(sheet).getByRole('button', { name: 'Save credential' }));
  await waitFor(() => expect(posted).toEqual({ name: 'router admin', kind: 'password', config: { username: 'admin', password: 'pw' } }));
});

it('the ssh kind renders no anyOf option picker', async () => {
  const { user } = renderRoute('/o/acme/delivery/credentials');
  await user.click(await screen.findByRole('button', { name: 'Add credential' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add credential' });
  expect(within(sheet).getByRole('radio', { name: 'SSH' })).toHaveAttribute('aria-checked', 'true');
  expect(within(sheet).queryByText(/Option 1/)).not.toBeInTheDocument();
});

it('the ssh kind Private key is a textarea with an Upload button', async () => {
  const { user } = renderRoute('/o/acme/delivery/credentials');
  await user.click(await screen.findByRole('button', { name: 'Add credential' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add credential' });
  expect(within(sheet).getByLabelText('Private key').tagName).toBe('TEXTAREA');
  expect(within(sheet).getByRole('button', { name: /Upload/ })).toBeInTheDocument();
});

it('edit keeps stored secrets, locks the kind and sends no kind', async () => {
  creds = [makeDeployCredential({ usedBy: 2 })];
  const { user } = renderRoute('/o/acme/delivery/credentials');
  await user.click(await screen.findByRole('button', { name: 'Edit lab ssh' }));
  const sheet = await screen.findByRole('dialog', { name: 'Edit lab ssh' });
  expect(within(sheet).getByRole('radio', { name: 'Password' })).toBeDisabled();
  await user.clear(within(sheet).getByLabelText('Username'));
  await user.type(within(sheet).getByLabelText('Username'), 'deploy');
  await user.click(within(sheet).getByRole('button', { name: 'Save credential' }));
  await waitFor(() => expect(put).toEqual({ name: 'lab ssh', config: { username: 'deploy', privateKey: UNCHANGED } }));
});

it('a global admin can reveal a stored secret', async () => {
  creds = [makeDeployCredential()];
  const { user } = renderRoute('/o/acme/delivery/credentials');
  await user.click(await screen.findByRole('button', { name: 'Edit lab ssh' }));
  const sheet = await screen.findByRole('dialog', { name: 'Edit lab ssh' });
  await user.click(within(sheet).getByRole('button', { name: "Reveal Private key" }));
  await waitFor(() => expect(revealed).toEqual({ field: 'privateKey' }));
});

it('reveal is disabled for an org admin', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: org.id }]))));
  creds = [makeDeployCredential()];
  const { user } = renderRoute('/o/acme/delivery/credentials');
  await user.click(await screen.findByRole('button', { name: 'Edit lab ssh' }));
  const sheet = await screen.findByRole('dialog', { name: 'Edit lab ssh' });
  expect(within(sheet).getByRole('button', { name: "Reveal Private key" })).toHaveAttribute('aria-disabled', 'true');
});

it('shows usage and disables Delete while targets use it', async () => {
  creds = [makeDeployCredential({ usedBy: 2 })];
  const { user } = renderRoute('/o/acme/delivery/credentials');
  const row = (await screen.findByText('lab ssh')).closest('tr')!;
  expect(within(row).getByText('2 targets')).toBeInTheDocument();
  const del = within(row).getByRole('button', { name: 'Delete lab ssh' });
  expect(del).toHaveAttribute('aria-disabled', 'true');
  await user.hover(del);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Used by 2 targets');
});

it('deletes an unused credential and shows a 409 inline', async () => {
  creds = [makeDeployCredential()];
  server.use(http.delete(url('/orgs/org-1/deploy-credentials/:id'), ({ params }) => {
    deleted = String(params.id);
    return problem(409, 'deploy credential is used by: edge ssh', {}, 'Conflict');
  }));
  const { user } = renderRoute('/o/acme/delivery/credentials');
  await user.click(await screen.findByRole('button', { name: 'Delete lab ssh' }));
  const dialog = screen.getByRole('dialog');
  await user.type(within(dialog).getByRole('textbox'), 'lab ssh');
  await user.click(within(dialog).getByRole('button', { name: 'Delete credential' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('edge ssh');
  expect(deleted).toBe('dc-1');
});

it('an operator sees credentials read-only', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))));
  creds = [makeDeployCredential()];
  const { user } = renderRoute('/o/acme/delivery/credentials');
  const add = await screen.findByRole('button', { name: 'Add credential' });
  expect(add).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'View lab ssh' }));
  const sheet = await screen.findByRole('dialog', { name: 'lab ssh' });
  expect(within(sheet).queryByRole('button', { name: 'Save credential' })).not.toBeInTheDocument();
});

it('the used-by count opens a popover of the targets, each linking to its target', async () => {
  creds = [makeDeployCredential({ usedBy: 2 })];
  let query = '';
  server.use(
    http.get(url('/orgs/org-1/deploy-targets'), ({ request }) => {
      query = new URL(request.url).search;
      return HttpResponse.json({ items: [makeTarget({ id: 't-7', name: 'edge a' }), makeTarget({ id: 't-8', name: 'edge b' })] });
    }),
  );
  const { user } = renderRoute('/o/acme/delivery/credentials');
  await user.click(await screen.findByRole('button', { name: '2 targets' }));
  expect(await screen.findByRole('link', { name: 'edge a' })).toHaveAttribute('href', '/o/acme/delivery/targets/t-7/overview');
  expect(screen.getByRole('link', { name: 'edge b' })).toBeInTheDocument();
  expect(new URLSearchParams(query).get('credentialId')).toBe(creds[0]!.id);
});
