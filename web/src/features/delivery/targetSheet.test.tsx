import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeTarget, meWith, org, targetTestSecret, targetVaultKv, testSecretSchema, traefikSchema, url, vaultKvSchema } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let posted: unknown;
let patched: unknown;

// setup.ts's default matchMedia says false (compact); most of this file
// wants the type segment's RunsOnChip showing its word, not just an
// aria-label, so start "desktop" and let the one compact test opt out.
function stubViewport(isSmUp: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 640px)' ? isSmUp : false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}

afterEach(() => vi.unstubAllGlobals());

beforeEach(() => {
  stubViewport(true);
  posted = undefined;
  patched = undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [makeTarget()] })),
    http.post(url('/orgs/org-1/deploy-targets'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json(makeTarget({ id: 't-new' }), { status: 201 });
    }),
    http.patch(url('/orgs/org-1/deploy-targets/:id'), async ({ request }) => {
      patched = await request.json();
      return HttpResponse.json(makeTarget());
    }),
  );
});

it('type segments show runs-on chip', async () => {
  server.use(http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema, testSecretSchema], notifiers: [], signers: [] })));
  renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  expect(within(within(sheet).getByRole('radio', { name: /^Vault KV/ })).getByText('Server')).toBeInTheDocument();
  expect(within(within(sheet).getByRole('radio', { name: /^Traefik/ })).getByText('Agent')).toBeInTheDocument();
  expect(within(within(sheet).getByRole('radio', { name: /^Test secret/ })).getByText('Server or agent')).toBeInTheDocument();
});

it('runs-on chip compact below sm', async () => {
  stubViewport(false);
  server.use(http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema], notifiers: [], signers: [] })));
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  const vaultRadio = within(sheet).getByRole('radio', { name: /^Vault KV/ });
  expect(within(vaultRadio).queryByText('Server')).not.toBeInTheDocument();
  // The chip's own tooltip trigger is a descendant of the radio, so hovering
  // the radio itself (an ancestor) never reaches it — find the compact
  // chip's own DOM node by its aria-label and hover that directly.
  const chip = vaultRadio.querySelector('[aria-label="Server"]');
  expect(chip).not.toBeNull();
  await user.hover(chip!);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Server');
});

it('forced type disables other segment with tooltip', async () => {
  server.use(http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema], notifiers: [], signers: [] })));
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  // traefik (agent-only) is the default type: its own Server segment is forced off.
  const serverOpt = within(sheet).getByRole('radio', { name: 'Server' });
  expect(serverOpt).toBeDisabled();
  await user.hover(serverOpt);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('This type can only run here.');
  expect(within(sheet).getByRole('radio', { name: 'Agent' })).toHaveAttribute('aria-checked', 'true');
});

it('either type defaults to agent and can pick server', async () => {
  server.use(http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, testSecretSchema], notifiers: [], signers: [] })));
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.click(within(sheet).getByRole('radio', { name: /^Test secret/ }));
  expect(within(sheet).getByRole('radio', { name: 'Agent' })).toHaveAttribute('aria-checked', 'true');
  await user.click(within(sheet).getByRole('radio', { name: 'Server' }));
  expect(within(sheet).getByRole('radio', { name: 'Server' })).toHaveAttribute('aria-checked', 'true');
});

it('type change resets config and runs-on', async () => {
  server.use(http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema], notifiers: [], signers: [] })));
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.type(within(sheet).getByLabelText('Directory on the agent'), '/etc/traefik/dynamic');
  await user.click(within(sheet).getByRole('radio', { name: /^Vault KV/ }));
  expect(within(sheet).queryByLabelText('Directory on the agent')).not.toBeInTheDocument();
  expect(within(sheet).getByLabelText('Mount')).toHaveValue('secret');
  expect(within(sheet).getByRole('radio', { name: 'Server' })).toHaveAttribute('aria-checked', 'true');
});

it('create posts runsOn', async () => {
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.type(within(sheet).getByLabelText('Name'), 'edge-2');
  await user.type(within(sheet).getByLabelText('Directory on the agent'), '/etc/traefik/dynamic');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toMatchObject({ name: 'edge-2', type: 'traefik', runsOn: 'agent' }));
});

it('runsOn locked on edit and absent from PATCH', async () => {
  const { user } = renderRoute('/o/acme/delivery/targets?edit=t-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit edge traefik' });
  expect(within(sheet).getByRole('radio', { name: 'Agent' })).toBeDisabled();
  expect(within(sheet).getByRole('radio', { name: 'Server' })).toBeDisabled();
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toBeDefined());
  expect(patched).not.toHaveProperty('runsOn');
});

it('secret field masked when stored', async () => {
  server.use(
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [testSecretSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [targetTestSecret] })),
  );
  renderRoute(`/o/acme/delivery/targets?edit=${targetTestSecret.id}`);
  const sheet = await screen.findByRole('dialog', { name: `Edit ${targetTestSecret.name}` });
  expect(await within(sheet).findByText('Stored')).toBeInTheDocument();
  expect(within(sheet).queryByLabelText('Token')).not.toBeInTheDocument();
});

it('edit sends sentinel for stored secrets', async () => {
  server.use(
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [testSecretSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [targetTestSecret] })),
  );
  const { user } = renderRoute(`/o/acme/delivery/targets?edit=${targetTestSecret.id}`);
  const sheet = await screen.findByRole('dialog', { name: `Edit ${targetTestSecret.name}` });
  await user.clear(within(sheet).getByLabelText('URL'));
  await user.type(within(sheet).getByLabelText('URL'), 'https://sink2.test');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toMatchObject({ config: { url: 'https://sink2.test', token: '__unchanged__' } }));
});

it('stored secret with schema default sends sentinel', async () => {
  server.use(
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [testSecretSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [targetTestSecret] })),
  );
  const { user } = renderRoute(`/o/acme/delivery/targets?edit=${targetTestSecret.id}`);
  const sheet = await screen.findByRole('dialog', { name: `Edit ${targetTestSecret.name}` });
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toMatchObject({ config: { token: '__unchanged__' } }));
});

it('replace sends new secret; remove sends empty', async () => {
  server.use(
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [testSecretSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [targetTestSecret] })),
  );
  const { user, router } = renderRoute(`/o/acme/delivery/targets?edit=${targetTestSecret.id}`);
  const sheet = await screen.findByRole('dialog', { name: `Edit ${targetTestSecret.name}` });
  await user.click(within(sheet).getByRole('button', { name: 'Replace Token' }));
  await user.type(within(sheet).getByLabelText('Token'), 'new-secret');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toMatchObject({ config: { token: 'new-secret' } }));
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('edit'));

  await router.navigate({ to: '/o/$org/delivery/targets', params: { org: 'acme' }, search: { edit: targetTestSecret.id } });
  const sheet2 = await screen.findByRole('dialog', { name: `Edit ${targetTestSecret.name}` });
  await user.click(within(sheet2).getByRole('button', { name: 'Remove Token' }));
  await user.click(within(sheet2).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toMatchObject({ config: { token: '' } }));
});

it('server segment disabled without keys:export for always types', async () => {
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, testSecretSchema], notifiers: [], signers: [] })),
  );
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.click(within(sheet).getByRole('radio', { name: /^Test secret/ }));
  const serverOpt = within(sheet).getByRole('radio', { name: 'Server' });
  expect(serverOpt).toBeDisabled();
  await user.hover(serverOpt);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the keys:export permission');
});

it('includeKey on a server target gates save', async () => {
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [{ ...targetVaultKv, config: { ...targetVaultKv.config, includeKey: true } }] })),
  );
  renderRoute(`/o/acme/delivery/targets?edit=${targetVaultKv.id}`);
  const sheet = await screen.findByRole('dialog', { name: `Edit ${targetVaultKv.name}` });
  expect(within(sheet).getByRole('button', { name: 'Save' })).toBeDisabled();
});

it('secrets tip only when schema has secrets', async () => {
  server.use(http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, testSecretSchema], notifiers: [], signers: [] })));
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  const settingsLabel = () => within(sheet).getByText('Settings').closest('span')!;
  expect(within(settingsLabel()).queryByRole('button', { name: 'Help' })).not.toBeInTheDocument();
  await user.click(within(sheet).getByRole('radio', { name: /^Test secret/ }));
  expect(within(settingsLabel()).getByRole('button', { name: 'Help' })).toBeInTheDocument();
});

it('target secrets not cached', async () => {
  server.use(http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [testSecretSchema], notifiers: [], signers: [] })));
  const { user, queryClient, router } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.type(within(sheet).getByLabelText('Name'), 'sink');
  await user.click(within(sheet).getByRole('radio', { name: /^Test secret/ }));
  await user.type(within(sheet).getByLabelText('URL'), 'https://sink.test');
  await user.type(within(sheet).getByLabelText('Token'), 's3cr3t-token');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toBeDefined());
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('edit'));

  expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  const cached = JSON.stringify(queryClient.getQueryCache().getAll().map((q) => q.state.data));
  expect(cached).not.toContain('s3cr3t-token');
});
