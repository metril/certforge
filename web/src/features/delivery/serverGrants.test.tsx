import { http, HttpResponse } from 'msw';
import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { help } from '@/lib/help';
import { server } from '@/test/server';
import { authHandlers, grantServer, makeCert, makeGrant, makeHookRun, makeLayout, makeTarget, meWith, NOW, org, targetTestSecret, targetVaultKv, testSecretSchema, traefikSchema, url, vaultKvSchema } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let posted: unknown;
let patched: unknown;
let deleted: string[];
let redeployed: string[];

// setup.ts's matchMedia says false, which would render the card list
// (clients/detail/grants.test.tsx's own precedent).
function stubViewport(isMdUp: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)' ? isMdUp : false,
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
  deleted = [];
  redeployed = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [makeTarget(), targetVaultKv] })),
    http.get(url('/orgs/org-1/deploy-targets/t-vault-1/grants'), () => HttpResponse.json([grantServer])),
    http.get(url('/orgs/org-1/certificates'), () =>
      HttpResponse.json({ items: [makeCert(), makeCert({ id: 'c-2', name: 'api', commonName: 'api.example.com' })], nextCursor: null }),
    ),
    http.get(url('/orgs/org-1/layouts'), () => HttpResponse.json({ items: [makeLayout()] })),
    http.post(url('/orgs/org-1/deploy-targets/t-vault-1/grants'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json(makeGrant({ id: 'g-new', runsOn: 'server', deployTargetId: 't-vault-1', clientId: null, clientName: null, deployment: null, serverDeployment: grantServer.serverDeployment }), {
        status: 201,
      });
    }),
    http.patch(url('/orgs/org-1/grants/:id'), async ({ request }) => {
      patched = await request.json();
      return HttpResponse.json(grantServer);
    }),
    http.delete(url('/orgs/org-1/grants/:id'), ({ params }) => {
      deleted.push(params.id as string);
      return new HttpResponse(null, { status: 204 });
    }),
    http.post(url('/orgs/org-1/grants/:id/redeploy'), ({ params }) => {
      redeployed.push(params.id as string);
      return HttpResponse.json(grantServer);
    }),
  );
});

const openDetail = () => renderRoute('/o/acme/delivery/targets?view=t-vault-1');

it('lists server grants with status', async () => {
  openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  expect(within(dialog).getByText('Server')).toBeInTheDocument();
  const table = await within(dialog).findByRole('table', { name: 'Grants' });
  const row = within(table).getByText('www').closest('tr')!;
  expect(within(row).getByText('nginx')).toBeInTheDocument();
  expect(within(row).getByText('Deployed')).toBeInTheDocument();
});

it('create posts certificate and layout', async () => {
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  await user.click(await within(dialog).findByRole('button', { name: 'New server grant' }));
  await user.click(within(dialog).getByRole('combobox', { name: 'Certificate' }));
  await user.click(await screen.findByRole('option', { name: /^api/ }));
  await user.click(within(dialog).getByRole('combobox', { name: 'Layout' }));
  await user.click(await screen.findByRole('option', { name: /^nginx/ }));
  await user.click(within(dialog).getByRole('button', { name: 'Grant' }));
  await waitFor(() => expect(posted).toEqual({ certificateId: 'c-2', layoutId: 'l-1' }));
});

it('creating and deleting a server grant refetches the targets list', async () => {
  // Final review: a server grant counts toward its target's own grantCount
  // (internal/db/queries/delivery.sql's DeployTargetGrantCounts), so the
  // Targets table behind this sheet must refetch too, not just the grants
  // list and certificates — otherwise its "Used by" count and Delete
  // blocking go stale.
  let targetGets = 0;
  server.use(
    http.get(url('/orgs/org-1/deploy-targets'), () => {
      targetGets++;
      return HttpResponse.json({ items: [makeTarget(), targetVaultKv] });
    }),
  );
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  await within(dialog).findByRole('table', { name: 'Grants' });
  const afterOpen = targetGets;

  await user.click(within(dialog).getByRole('button', { name: 'New server grant' }));
  await user.click(within(dialog).getByRole('combobox', { name: 'Certificate' }));
  await user.click(await screen.findByRole('option', { name: /^api/ }));
  await user.click(within(dialog).getByRole('button', { name: 'Grant' }));
  await waitFor(() => expect(posted).toEqual({ certificateId: 'c-2', layoutId: null }));
  await waitFor(() => expect(targetGets).toBeGreaterThan(afterOpen));
  const afterCreate = targetGets;

  await user.click(within(dialog).getByRole('button', { name: 'Remove www' }));
  const confirm = await screen.findByRole('dialog', { name: 'Remove grant?' });
  await user.type(within(confirm).getByRole('textbox'), 'www');
  await user.click(within(confirm).getByRole('button', { name: 'Remove' }));
  await waitFor(() => expect(deleted).toEqual([grantServer.id]));
  await waitFor(() => expect(targetGets).toBeGreaterThan(afterCreate));
});

it('non-PEM layouts disabled', async () => {
  server.use(
    http.get(url('/orgs/org-1/layouts'), () =>
      HttpResponse.json({ items: [makeLayout(), makeLayout({ id: 'l-2', name: 'p12 bundle', files: [{ path: '/x.p12', format: 'p12', parts: [], owner: '', group: '', mode: '0640' }] })] }),
    ),
  );
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  await user.click(await within(dialog).findByRole('button', { name: 'New server grant' }));
  await user.click(within(dialog).getByRole('combobox', { name: 'Layout' }));
  const opt = await screen.findByRole('option', { name: /^p12 bundle/ });
  expect(opt).toHaveAttribute('aria-disabled', 'true');
  await user.hover(opt);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('PEM layouts only');
});

it('edit sends layout only', async () => {
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  await within(dialog).findByRole('table', { name: 'Grants' });
  await user.click(within(dialog).getByRole('button', { name: 'Edit layout for www' }));
  const certBox = await within(dialog).findByRole('combobox', { name: 'Certificate' });
  expect(certBox).toBeDisabled();
  await user.click(within(dialog).getByRole('combobox', { name: 'Layout' }));
  await user.click(await screen.findByRole('option', { name: 'Target files' }));
  await user.click(within(dialog).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toEqual({ layoutId: null }));
});

it('redeploy toasts queued', async () => {
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  await within(dialog).findByRole('table', { name: 'Grants' });
  await user.click(within(dialog).getByRole('button', { name: 'Redeploy www' }));
  await waitFor(() => expect(redeployed).toEqual([grantServer.id]));
  expect(await screen.findByText('Redeploy queued')).toBeInTheDocument();
});

it('delete confirms', async () => {
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  await within(dialog).findByRole('table', { name: 'Grants' });
  await user.click(within(dialog).getByRole('button', { name: 'Remove www' }));
  const confirm = await screen.findByRole('dialog', { name: 'Remove grant?' });
  expect(confirm).toHaveTextContent('what is already there stays');
  await user.type(within(confirm).getByRole('textbox'), 'www');
  await user.click(within(confirm).getByRole('button', { name: 'Remove' }));
  await waitFor(() => expect(deleted).toEqual([grantServer.id]));
});

it('includeKey needs keys:export', async () => {
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))),
    http.get(url('/orgs/org-1/deploy-targets/t-vault-1/grants'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/deploy-targets'), () =>
      HttpResponse.json({ items: [{ ...targetVaultKv, config: { ...targetVaultKv.config, includeKey: true } }] }),
    ),
  );
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  const button = await within(dialog).findByRole('button', { name: 'New server grant' });
  expect(button).toBeDisabled();
  await user.hover(button);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the keys:export permission');
});

it('edit layout needs keys:export on an includeKey target', async () => {
  // Batch 4 review: updateServerGrant's requireKeyIfNeeded gate means an
  // includeKey target needs keys:export to edit any grant's layout, not
  // just clients:write — a clients:write-only operator must see Edit
  // layout disabled with that reason, same as New server grant.
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))),
    http.get(url('/orgs/org-1/deploy-targets'), () =>
      HttpResponse.json({ items: [{ ...targetVaultKv, config: { ...targetVaultKv.config, includeKey: true } }] }),
    ),
  );
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  const table = await within(dialog).findByRole('table', { name: 'Grants' });
  const editBtn = within(table).getByRole('button', { name: 'Edit layout for www' });
  expect(editBtn).toHaveAttribute('aria-disabled', 'true');
  await user.hover(editBtn);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the keys:export permission');
});

// Task 4: keyed now comes from needsKey(typeMeta(...).keyPolicy, config),
// not a raw includeKey read, so an `always`-policy type (test-secret) gates
// New server grant even without an includeKey field at all.
it('new server grant needs keys:export for always', async () => {
  server.use(
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema, testSecretSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [targetTestSecret] })),
    http.get(url('/orgs/org-1/deploy-targets/t-test-secret-1/grants'), () => HttpResponse.json([])),
  );
  const { user } = renderRoute('/o/acme/delivery/targets?view=t-test-secret-1');
  const dialog = await screen.findByRole('dialog', { name: 'test sink' });
  const button = await within(dialog).findByRole('button', { name: 'New server grant' });
  expect(button).toBeDisabled();
  await user.hover(button);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the keys:export permission');
});

it('never or unset key policy needs only clients:write', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))));
  openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  const button = await within(dialog).findByRole('button', { name: 'New server grant' });
  expect(button).toBeEnabled();
});

it('header shows runs-on, key and secrets chips', async () => {
  server.use(
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema, vaultKvSchema, testSecretSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [targetTestSecret] })),
    http.get(url('/orgs/org-1/deploy-targets/t-test-secret-1/grants'), () => HttpResponse.json([])),
  );
  const { user } = renderRoute('/o/acme/delivery/targets?view=t-test-secret-1');
  const dialog = await screen.findByRole('dialog', { name: 'test sink' });
  expect(within(dialog).getByText('Test secret')).toBeInTheDocument();
  expect(within(dialog).getByText('Server')).toBeInTheDocument();
  expect(within(dialog).getByText('Includes key')).toBeInTheDocument();
  const secretsChip = within(dialog).getByText('Stored secrets');
  await user.hover(secretsChip);
  expect(await screen.findByRole('tooltip')).toHaveTextContent(help['target.secrets'].text);
});

it('needs clients:write', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  const table = await within(dialog).findByRole('table', { name: 'Grants' });
  const row = within(table).getByText('www').closest('tr')!;
  const redeployBtn = within(row).getByRole('button', { name: 'Redeploy www' });
  expect(redeployBtn).toHaveAttribute('aria-disabled', 'true');
  await user.hover(redeployBtn);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the clients:write permission');
});

it('agent target id shows not found', async () => {
  renderRoute('/o/acme/delivery/targets?view=t-1');
  await screen.findByRole('table', { name: 'Deploy targets' });
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(await screen.findByText('Deploy target not found.')).toBeInTheDocument();
});

it('a not-found ?view= replaces the history entry instead of pushing one', async () => {
  const { router } = renderRoute('/o/acme/delivery/targets?view=t-1');
  await screen.findByText('Deploy target not found.');
  expect(router.history.length).toBe(1);
});

it('stops polling when settled', async () => {
  vi.useFakeTimers({ now: NOW, toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
  let getCalls = 0;
  const pending = { ...grantServer, serverDeployment: { ...grantServer.serverDeployment!, status: 'pending' as const, deployedAt: null } };
  let settled = false;
  server.use(
    http.get(url('/orgs/org-1/deploy-targets/t-vault-1/grants'), () => {
      getCalls++;
      return HttpResponse.json([settled ? grantServer : pending]);
    }),
  );
  // Fake timers block testing-library's own findBy* polling (it also runs
  // on setTimeout), so this ticks and re-queries by hand, matching
  // settings/keys.test.tsx's "polls only while running" precedent.
  const tick = (ms: number) =>
    act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
    });
  renderRoute('/o/acme/delivery/targets?view=t-vault-1');
  for (let i = 0; i < 20 && !screen.queryByText('Pending'); i++) await tick(50);
  expect(screen.getByText('Pending')).toBeInTheDocument();
  const beforeSettle = getCalls;
  settled = true;
  for (let i = 0; i < 60 && !screen.queryByText('Deployed'); i++) await tick(50);
  expect(screen.getByText('Deployed')).toBeInTheDocument();
  const afterSettle = getCalls;
  expect(afterSettle).toBeGreaterThan(beforeSettle);
  await tick(10_000);
  expect(getCalls).toBe(afterSettle);
  vi.useRealTimers();
});

const sshTarget = makeTarget({ id: 't-ssh', name: 'bastion', type: 'ssh', runsOn: 'server', config: { host: 'h' } });

it('create posts the post action', async () => {
  server.use(http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [makeTarget(), targetVaultKv, sshTarget] })));
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  await user.click(await within(dialog).findByRole('button', { name: 'New server grant' }));
  await user.click(within(dialog).getByRole('combobox', { name: 'Certificate' }));
  await user.click(await screen.findByRole('option', { name: /^api/ }));
  await user.click(within(dialog).getByRole('switch', { name: 'Post action' }));
  await user.click(within(dialog).getByRole('combobox', { name: 'SSH target' }));
  const opts = await screen.findAllByRole('option');
  expect(opts.map((o) => o.textContent)).toEqual(['bastion']);
  await user.click(opts[0]!);
  await user.type(within(dialog).getByLabelText('Command'), 'systemctl reload nginx');
  await user.click(within(dialog).getByRole('button', { name: 'Grant' }));
  await waitFor(() =>
    expect(posted).toEqual({
      certificateId: 'c-2',
      layoutId: null,
      postAction: { kind: 'ssh', targetId: 't-ssh', command: 'systemctl reload nginx', timeoutSeconds: 60 },
    }),
  );
});

it('post action needs a target and command', async () => {
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  await user.click(await within(dialog).findByRole('button', { name: 'New server grant' }));
  await user.click(within(dialog).getByRole('combobox', { name: 'Certificate' }));
  await user.click(await screen.findByRole('option', { name: /^api/ }));
  await user.click(within(dialog).getByRole('switch', { name: 'Post action' }));
  await user.click(within(dialog).getByRole('button', { name: 'Grant' }));
  expect(await within(dialog).findByText('Pick an SSH target and enter a command.')).toBeInTheDocument();
  expect(posted).toBeUndefined();
});

it('hook runs tab lists the target runs', async () => {
  server.use(
    http.get(url('/orgs/org-1/deploy-targets/t-vault-1/hook-runs'), () =>
      HttpResponse.json({ items: [makeHookRun({ id: 'hr-s', hookId: null, hookName: '', argv: ['ssh', 'bastion', 'systemctl reload nginx'], exitCode: 3, stderr: 'boom' })], nextCursor: null }),
    ),
  );
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  await user.click(within(dialog).getByRole('tab', { name: 'Hook runs' }));
  const list = await within(dialog).findByRole('list', { name: 'Hook runs' });
  expect(within(list).getByText('SSH command')).toBeInTheDocument();
  expect(within(list).getByText('ssh bastion systemctl reload nginx')).toBeInTheDocument();
  expect(within(list).getByText('3')).toBeInTheDocument();
});

const pfTarget = makeTarget({ id: 't-pf', name: 'edge fw', type: 'pfsense', runsOn: 'server', config: { url: 'https://fw.example.net/api' } });

it('pfSense kind prefills the restart command and posts it', async () => {
  server.use(http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [makeTarget(), targetVaultKv, sshTarget, pfTarget] })));
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  await user.click(await within(dialog).findByRole('button', { name: 'New server grant' }));
  await user.click(within(dialog).getByRole('combobox', { name: 'Certificate' }));
  await user.click(await screen.findByRole('option', { name: /^api/ }));
  await user.click(within(dialog).getByRole('switch', { name: 'Post action' }));
  expect(within(dialog).getByRole('radio', { name: 'SSH' })).toBeChecked();
  await user.click(within(dialog).getByRole('radio', { name: 'pfSense' }));
  expect(within(dialog).getByLabelText('Command')).toHaveValue('/etc/rc.restart_webgui');
  await user.click(within(dialog).getByRole('combobox', { name: 'pfSense target' }));
  const opts = await screen.findAllByRole('option');
  expect(opts.map((o) => o.textContent)).toEqual(['edge fw']);
  await user.click(opts[0]!);
  await user.click(within(dialog).getByRole('button', { name: 'Grant' }));
  await waitFor(() =>
    expect(posted).toEqual({
      certificateId: 'c-2',
      layoutId: null,
      postAction: { kind: 'pfsense', targetId: 't-pf', command: '/etc/rc.restart_webgui', timeoutSeconds: 60 },
    }),
  );
});

it('switching back to SSH clears the prefilled command', async () => {
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  await user.click(await within(dialog).findByRole('button', { name: 'New server grant' }));
  await user.click(within(dialog).getByRole('switch', { name: 'Post action' }));
  await user.click(within(dialog).getByRole('radio', { name: 'pfSense' }));
  await user.click(within(dialog).getByRole('radio', { name: 'SSH' }));
  expect(within(dialog).getByLabelText('Command')).toHaveValue('');
});

it('pfSense target grants check usage on demand', async () => {
  let calls = 0;
  server.use(
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [pfTarget] })),
    http.get(url('/orgs/org-1/deploy-targets/t-pf/grants'), () => HttpResponse.json([{ ...grantServer, deployTargetId: 't-pf' }])),
    http.get(url('/orgs/org-1/grants/g-server-1/pfsense-usage'), () => {
      calls++;
      return HttpResponse.json(calls === 1 ? { refid: 'abc', services: [{ key: 'webgui', label: 'WebGUI' }, { key: 'openvpn:server:1', label: 'OpenVPN server 1' }] } : { refid: 'abc', services: [] });
    }),
  );
  const { user } = renderRoute('/o/acme/delivery/targets?view=t-pf');
  const dialog = await screen.findByRole('dialog', { name: 'edge fw' });
  expect(await within(dialog).findByText('Used on pfSense by')).toBeInTheDocument();
  expect(calls).toBe(0);
  await user.click(within(dialog).getByRole('button', { name: 'Check usage' }));
  const list = await within(dialog).findByRole('list', { name: 'Services' });
  expect(within(list).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['WebGUI', 'OpenVPN server 1']);
  await user.click(within(dialog).getByRole('button', { name: 'Check usage' }));
  expect(await within(dialog).findByText('No services use it')).toBeInTheDocument();
});

function pfGrantRoutes(options: Record<string, unknown> = {}) {
  server.use(
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [pfTarget] })),
    http.get(url('/orgs/org-1/deploy-targets/t-pf/grants'), () => HttpResponse.json([{ ...grantServer, deployTargetId: 't-pf', targetOptions: options }])),
    http.post(url('/orgs/org-1/deploy-targets/t-pf/grants'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json({ ...grantServer, id: 'g-new', deployTargetId: 't-pf' }, { status: 201 });
    }),
    http.get(url('/orgs/org-1/grants/g-server-1/pfsense-usage'), () =>
      HttpResponse.json({ refid: 'abc', services: [{ key: 'webgui', label: 'WebGUI' }, { key: 'openvpn:server:1', label: 'OpenVPN server 1' }] }),
    ),
  );
}

it('new pfSense grant: restart mode defaults to all, Only these waits for a first deploy', async () => {
  pfGrantRoutes();
  const { user } = renderRoute('/o/acme/delivery/targets?view=t-pf');
  const dialog = await screen.findByRole('dialog', { name: 'edge fw' });
  await user.click(await within(dialog).findByRole('button', { name: 'New server grant' }));
  const group = within(dialog).getByRole('radiogroup', { name: 'Restart services' });
  expect(within(group).getByRole('radio', { name: 'All that use it' })).toBeChecked();
  expect(within(group).getByRole('radio', { name: 'Only these' })).toBeDisabled();
  expect(within(dialog).getByText(/available after the first deploy/)).toBeInTheDocument();
  await user.click(within(dialog).getByRole('combobox', { name: 'Certificate' }));
  await user.click(await screen.findByRole('option', { name: /^api/ }));
  await user.click(within(dialog).getByRole('button', { name: 'Grant' }));
  await waitFor(() => expect(posted).toEqual({ certificateId: 'c-2', layoutId: null }));
});

it('new pfSense grant posts restart none', async () => {
  pfGrantRoutes();
  const { user } = renderRoute('/o/acme/delivery/targets?view=t-pf');
  const dialog = await screen.findByRole('dialog', { name: 'edge fw' });
  await user.click(await within(dialog).findByRole('button', { name: 'New server grant' }));
  await user.click(within(dialog).getByRole('combobox', { name: 'Certificate' }));
  await user.click(await screen.findByRole('option', { name: /^api/ }));
  await user.click(within(dialog).getByRole('radio', { name: 'None' }));
  await user.click(within(dialog).getByRole('button', { name: 'Grant' }));
  await waitFor(() => expect(posted).toEqual({ certificateId: 'c-2', layoutId: null, targetOptions: { pfsenseRestart: { mode: 'none' } } }));
});

it('editing a pfSense grant toggles services, keeps ones no longer in use, and saves the selection', async () => {
  pfGrantRoutes({ pfsenseRestart: { mode: 'selected', services: ['webgui', 'ipsec'] } });
  const { user } = renderRoute('/o/acme/delivery/targets?view=t-pf');
  const dialog = await screen.findByRole('dialog', { name: 'edge fw' });
  await user.click(await within(dialog).findByRole('button', { name: 'Edit layout for www' }));
  expect(within(dialog).getByRole('radio', { name: 'Only these' })).toBeChecked();
  const chips = await within(dialog).findByRole('toolbar', { name: 'Services to restart' });
  expect(await within(chips).findByRole('button', { name: 'WebGUI' })).toHaveAttribute('aria-pressed', 'true');
  expect(within(chips).getByRole('button', { name: 'OpenVPN server 1' })).toHaveAttribute('aria-pressed', 'false');
  expect(within(chips).getByRole('button', { name: 'ipsec (not in use)' })).toHaveAttribute('aria-pressed', 'true');
  await user.click(within(chips).getByRole('button', { name: 'OpenVPN server 1' }));
  await user.click(within(chips).getByRole('button', { name: 'WebGUI' }));
  await user.click(within(dialog).getByRole('button', { name: 'Save' }));
  await waitFor(() =>
    expect(patched).toEqual({ layoutId: 'l-1', targetOptions: { pfsenseRestart: { mode: 'selected', services: ['ipsec', 'openvpn:server:1'] } } }),
  );
});

it('Only these with nothing picked is refused', async () => {
  pfGrantRoutes();
  const { user } = renderRoute('/o/acme/delivery/targets?view=t-pf');
  const dialog = await screen.findByRole('dialog', { name: 'edge fw' });
  await user.click(await within(dialog).findByRole('button', { name: 'Edit layout for www' }));
  await user.click(within(dialog).getByRole('radio', { name: 'Only these' }));
  await within(dialog).findByRole('button', { name: 'WebGUI' });
  await user.click(within(dialog).getByRole('button', { name: 'Save' }));
  expect(await within(dialog).findByText('Pick at least one service, or choose None.')).toBeInTheDocument();
  expect(patched).toBeUndefined();
});

it('pfSense grant inherits restartServices false from the target and sends nothing until changed', async () => {
  pfGrantRoutes();
  server.use(http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [{ ...pfTarget, config: { url: 'https://fw.example.net/api', restartServices: false } }] })));
  const { user } = renderRoute('/o/acme/delivery/targets?view=t-pf');
  const dialog = await screen.findByRole('dialog', { name: 'edge fw' });
  await user.click(await within(dialog).findByRole('button', { name: 'New server grant' }));
  expect(await within(dialog).findByRole('radio', { name: 'None' })).toBeChecked();
  expect(within(dialog).getByText('(target default)')).toBeInTheDocument();
  await user.click(within(dialog).getByRole('combobox', { name: 'Certificate' }));
  await user.click(await screen.findByRole('option', { name: /^api/ }));
  await user.click(within(dialog).getByRole('button', { name: 'Grant' }));
  await waitFor(() => expect(posted).toEqual({ certificateId: 'c-2', layoutId: null }));
});
