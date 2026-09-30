import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeTarget, meWith, org, problem, targetVaultKv, traefikSchema, url, vaultKvSchema } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let posted: unknown;
let deleted: string[];

beforeEach(() => {
  posted = undefined;
  deleted = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () =>
      HttpResponse.json({ items: [makeTarget({ grantCount: 2 }), makeTarget({ id: 't-2', name: 'spare', config: { dir: '/srv/traefik' }, grantCount: 0 })] }),
    ),
    http.post(url('/orgs/org-1/deploy-targets'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json(makeTarget({ id: 't-3' }), { status: 201 });
    }),
    http.delete(url('/orgs/org-1/deploy-targets/:id'), ({ params }) => {
      deleted.push(params.id as string);
      return new HttpResponse(null, { status: 204 });
    }),
  );
});

// getAllByText + [0]: the Name column comes before the Type column in DOM
// order, and a target's name can collide with its own type's display name
// (e.g. a "Vault KV" target of type vault-kv, whose display name is also
// "Vault KV" now that RunsOnChip — not a name suffix — carries where it
// runs); the first match is always the Name cell.
const rowOf = (name: string) => screen.getAllByText(name, { selector: 'td' })[0]!.closest('tr')!;

it('opens from the nav and lists targets with type, directory and use', async () => {
  const { router } = renderRoute('/o/acme/delivery');
  await screen.findByRole('table', { name: 'Deploy targets' });
  expect(router.state.location.pathname).toBe('/o/acme/delivery/targets');
  const row = rowOf('edge traefik');
  for (const text of ['Traefik (file provider)', 'Agent', '/etc/traefik/dynamic', '2 grants']) expect(within(row).getByText(text)).toBeInTheDocument();
  expect(within(rowOf('spare')).getByText('–')).toBeInTheDocument();
});

it('adds a Traefik target from its schema form', async () => {
  const { user, router } = renderRoute('/o/acme/delivery/targets');
  await user.click(await screen.findByRole('button', { name: 'Add target' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.type(within(sheet).getByLabelText('Name'), 'edge-2');
  await user.type(within(sheet).getByLabelText('Directory on the agent'), '/etc/traefik/dynamic');
  await user.click(within(sheet).getByRole('switch', { name: 'Default certificate' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toMatchObject({ name: 'edge-2', type: 'traefik', config: { dir: '/etc/traefik/dynamic', defaultCert: true } }));
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('edit'));
});

it('shows the Traefik ACME service URL field from its schema and saves it under config.acmeServiceUrl', async () => {
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.type(within(sheet).getByLabelText('Name'), 'edge-3');
  await user.type(within(sheet).getByLabelText('Directory on the agent'), '/etc/traefik/dynamic');
  await user.type(within(sheet).getByLabelText('ACME service URL'), 'http://agent.internal:8080');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toMatchObject({ config: { dir: '/etc/traefik/dynamic', acmeServiceUrl: 'http://agent.internal:8080' } }));
});

it('refuses a relative directory before sending', async () => {
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.type(within(sheet).getByLabelText('Name'), 'bad');
  await user.type(within(sheet).getByLabelText('Directory on the agent'), 'traefik');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await within(sheet).findByText(/does not match pattern/i);
  expect(screen.getByRole('dialog', { name: 'Add deploy target' })).toBeInTheDocument();
  expect(posted).toBeUndefined();
});

it('blocks deleting a target in use and deletes an unused one by name', async () => {
  const { user } = renderRoute('/o/acme/delivery/targets');
  await screen.findByRole('table', { name: 'Deploy targets' });
  expect(screen.getByRole('button', { name: 'Delete edge traefik' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Delete spare' }));
  await user.type(screen.getByLabelText(/to confirm/), 'spare');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  await waitFor(() => expect(deleted).toEqual(['t-2']));
});

it('shows a raced 409 inside the delete dialog', async () => {
  server.use(http.delete(url('/orgs/org-1/deploy-targets/:id'), () => problem(409, 'Used by web-1/www.')));
  const { user } = renderRoute('/o/acme/delivery/targets');
  await user.click(await screen.findByRole('button', { name: 'Delete spare' }));
  await user.type(screen.getByLabelText(/to confirm/), 'spare');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  expect(await within(screen.getByRole('dialog')).findByText('Used by web-1/www.')).toBeInTheDocument();
});

it('is read-only for a viewer', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  const { user } = renderRoute('/o/acme/delivery/targets');
  expect(await screen.findByRole('button', { name: 'Add target' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'View edge traefik' }));
  const sheet = await screen.findByRole('dialog', { name: 'edge traefik' });
  expect(within(sheet).getByLabelText('Name')).toBeDisabled();
  expect(within(sheet).queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
});

it('is not available under All orgs', async () => {
  const { router } = renderRoute('/o/all/delivery/targets');
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/all/overview'));
});

it('edits a target with a PATCH carrying name, type and config', async () => {
  let patched: unknown;
  server.use(
    http.patch(url('/orgs/org-1/deploy-targets/:id'), async ({ request }) => {
      patched = await request.json();
      return HttpResponse.json(makeTarget({ name: 'renamed' }));
    }),
  );
  const { user } = renderRoute('/o/acme/delivery/targets?edit=t-2');
  const sheet = await screen.findByRole('dialog', { name: 'Edit spare' });
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toMatchObject({ name: 'spare', type: 'traefik', config: { dir: '/srv/traefik' } }));
  expect(Object.keys(patched as object).sort()).toEqual(['config', 'name', 'type']);
});

it('shows stores as chips and a field description as a tooltip', async () => {
  server.use(
    http.get(url('/orgs/org-1/deploy-targets'), () =>
      HttpResponse.json({ items: [makeTarget({ config: { dir: '/etc/traefik/dynamic', stores: ['default', 'internal'] } })] }),
    ),
  );
  const { user } = renderRoute('/o/acme/delivery/targets?edit=t-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit edge traefik' });
  expect(within(sheet).getByText('default')).toBeInTheDocument();
  expect(within(sheet).getByText('internal')).toBeInTheDocument();
  const dirLabel = within(sheet).getByText('Directory on the agent');
  await user.hover(within(dirLabel.closest('div')!).getByRole('button', { name: 'Help' }));
  expect(await screen.findByRole('tooltip')).toHaveTextContent("Traefik's file-provider directory as the agent sees it.");
});

it('surfaces a failed meta/schemas fetch with a retry and a disabled, explained Add button', async () => {
  server.use(http.get(url('/meta/schemas'), () => problem(500, 'boom')));
  renderRoute('/o/acme/delivery/targets');
  await screen.findByRole('table', { name: 'Deploy targets' });
  expect(await screen.findByText("Couldn't load target types. boom")).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Add target' })).toBeDisabled();
});

it('clears an unknown ?edit= id and reports it', async () => {
  renderRoute('/o/acme/delivery/targets?edit=nope');
  await screen.findByRole('table', { name: 'Deploy targets' });
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(await screen.findByText('Deploy target not found.')).toBeInTheDocument();
});

it('never opens the add sheet for a viewer, even with ?edit=new', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  renderRoute('/o/acme/delivery/targets?edit=new');
  await screen.findByRole('table', { name: 'Deploy targets' });
  expect(screen.queryByRole('dialog', { name: 'Add deploy target' })).not.toBeInTheDocument();
});

it('puts a name-conflict 409 under Name and any other 409 in the page alert', async () => {
  server.use(http.post(url('/orgs/org-1/deploy-targets'), () => problem(409, 'A deploy target named "edge traefik" already exists.')));
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.type(within(sheet).getByLabelText('Name'), 'edge traefik');
  await user.type(within(sheet).getByLabelText('Directory on the agent'), '/etc/traefik/dynamic');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await within(sheet).findByText('A deploy target named "edge traefik" already exists.')).toBeInTheDocument();
  expect(within(sheet).getByLabelText('Name')).toHaveAttribute('aria-invalid', 'true');

  server.use(http.post(url('/orgs/org-1/deploy-targets'), () => problem(409, 'Used by web-1/www.')));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  const alert = await within(sheet).findByText('Used by web-1/www.');
  expect(alert.closest('[role="alert"]')).toBeInTheDocument();
  expect(within(sheet).getByLabelText('Name')).not.toHaveAttribute('aria-invalid', 'true');
});

// Task 8/7B: the Vault KV target type and its includeKey gating. The type
// picker's own "runs on" hint is now RunsOnChip inside the segment label
// (task-2-brief.md), not a hover tooltip — TargetSheet.test.tsx covers the
// chip itself; this just proves every meta type still gets one.
it('type segments list every meta type', async () => {
  server.use(http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema], notifiers: [], signers: [] })));
  renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  expect(within(sheet).getByRole('radio', { name: /^Traefik \(file provider\)/ })).toBeInTheDocument();
  expect(within(sheet).getByRole('radio', { name: /^Vault KV/ })).toBeInTheDocument();
});

it('creates a vault-kv target with its default config', async () => {
  server.use(http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema], notifiers: [], signers: [] })));
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.type(within(sheet).getByLabelText('Name'), 'vault-store');
  // RunsOnChip's own visible/aria-label text ("Server") joins the type
  // name in the radio's accessible name now, so an exact "Vault KV" match
  // no longer resolves it — anchor on the type name alone instead.
  await user.click(within(sheet).getByRole('radio', { name: /^Vault KV/ }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toMatchObject({ name: 'vault-store', type: 'vault-kv', config: { includeKey: false } }));
});

it('disables includeKey without keys:export, with a tooltip naming it', async () => {
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema], notifiers: [], signers: [] })),
  );
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.click(within(sheet).getByRole('radio', { name: /^Vault KV/ }));
  const sw = await within(sheet).findByRole('switch', { name: 'Include private key' });
  expect(sw).toBeDisabled();
  await user.hover(sw);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the keys:export permission');
});

it('shows Server for a vault-kv row and a Grants action that opens its detail', async () => {
  server.use(
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [makeTarget(), targetVaultKv] })),
  );
  const { user, router } = renderRoute('/o/acme/delivery/targets');
  await screen.findByRole('table', { name: 'Deploy targets' });
  const row = rowOf(targetVaultKv.name);
  expect(within(row).getByText('Server')).toBeInTheDocument();
  expect(within(rowOf('edge traefik')).getByText('Agent')).toBeInTheDocument();
  await user.click(within(row).getByRole('button', { name: `Grants ${targetVaultKv.name}` }));
  expect(router.state.location.search).toMatchObject({ view: targetVaultKv.id });
});
