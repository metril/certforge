import { http, HttpResponse } from 'msw';
import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, grantServer, makeCert, makeGrant, makeLayout, makeTarget, meWith, NOW, org, targetVaultKv, traefikSchema, url, vaultKvSchema } from '@/test/fixtures';
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
  expect(within(dialog).getByText('Runs on server')).toBeInTheDocument();
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
  expect(confirm).toHaveTextContent('data already in Vault stays');
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
  expect(editBtn).toBeDisabled();
  await user.hover(editBtn);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the keys:export permission');
});

it('needs clients:write', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  const { user } = openDetail();
  const dialog = await screen.findByRole('dialog', { name: 'Vault KV' });
  const table = await within(dialog).findByRole('table', { name: 'Grants' });
  const row = within(table).getByText('www').closest('tr')!;
  const redeployBtn = within(row).getByRole('button', { name: 'Redeploy www' });
  expect(redeployBtn).toBeDisabled();
  await user.hover(redeployBtn);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the clients:write permission');
});

it('agent target id shows not found', async () => {
  renderRoute('/o/acme/delivery/targets?view=t-1');
  await screen.findByRole('table', { name: 'Deploy targets' });
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(await screen.findByText('Deploy target not found.')).toBeInTheDocument();
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
