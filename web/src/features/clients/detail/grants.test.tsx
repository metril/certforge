import { http, HttpResponse } from 'msw';
import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Grant } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, grantServer, iso, makeClient, makeDeployment, makeGrant, makeHook, makeLayout, makeTarget, meWith, org, problem, targetVaultKv, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

const a = 'aa'.repeat(32);
const b = 'bb'.repeat(32);
let grants: Grant[];
let calls: string[];

// setup.ts's matchMedia says false, which would render the card list.
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
  calls = [];
  grants = [
    makeGrant({ id: 'g-1', certificateId: 'c-1', certificateName: 'www', hookIds: ['h-1'], autoRemediate: true }),
    makeGrant({
      id: 'g-2', certificateId: 'c-2', certificateName: 'api', delivery: 'pull', layoutId: null, deployTargetId: 't-1',
      deployment: makeDeployment({
        state: 'drift',
        expected: [{ path: '/etc/traefik/dynamic/certforge-api.yml', sha256: a }, { path: '/etc/traefik/dynamic/certs/api/privkey.pem', sha256: a }],
        installed: [{ path: '/etc/traefik/dynamic/certforge-api.yml', sha256: b }],
      }),
    }),
    makeGrant({ id: 'g-3', certificateId: 'c-3', certificateName: 'mail', deployment: makeDeployment({ state: 'failed', error: 'chown: unknown user nginx' }) }),
  ];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/clients/cl-1'), () => HttpResponse.json(makeClient())),
    http.get(url('/orgs/org-1/clients/cl-1/grants'), () => HttpResponse.json({ items: grants })),
    http.get(url('/orgs/org-1/layouts'), () => HttpResponse.json({ items: [makeLayout()] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [makeTarget()] })),
    http.get(url('/orgs/org-1/hooks'), () => HttpResponse.json({ items: [makeHook()] })),
    http.post(url('/orgs/org-1/grants/:id/redeploy'), ({ params }) => {
      calls.push(`redeploy ${params.id}`);
      return HttpResponse.json(grants.find((g) => g.id === params.id));
    }),
    http.delete(url('/orgs/org-1/grants/:id'), ({ params, request }) => {
      const forced = new URL(request.url).searchParams.get('force') === 'true';
      calls.push(`delete ${params.id}${forced ? ' force' : ''}`);
      grants = grants.filter((g) => g.id !== params.id);
      return new HttpResponse(null, { status: 204 });
    }),
  );
});

const rowOf = (name: string) => screen.getByRole('link', { name }).closest('tr')!;

// findByRole also matches the loading skeleton (same aria-label, no row
// text yet), so a synchronous rowOf right after it can race the fetch;
// wait for the skeleton's aria-busy to clear before reading row content.
async function findLoadedTable(name = 'Grants') {
  const table = await screen.findByRole('table', { name });
  await waitFor(() => expect(table).not.toHaveAttribute('aria-busy', 'true'));
  return table;
}

it('is the default tab and lists grants with delivery, layout, target, hooks and state', async () => {
  const { router } = renderRoute('/o/acme/clients/cl-1');
  await findLoadedTable();
  expect(router.state.location.pathname).toBe('/o/acme/clients/cl-1/certificates');
  const www = rowOf('www');
  for (const text of ['Push', 'nginx', '1', 'On', 'Deployed']) expect(within(www).getByText(text)).toBeInTheDocument();
  const api = rowOf('api');
  for (const text of ['Pull', 'edge traefik', 'Off', 'Drift']) expect(within(api).getByText(text)).toBeInTheDocument();
  expect(within(rowOf('mail')).getByText('Failed')).toBeInTheDocument();
});

it('expands a drift row from the URL with expected against installed files', async () => {
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates?open=g-2');
  const files = await screen.findByRole('list', { name: 'Files for api' });
  const [yml, key] = within(files).getAllByRole('listitem');
  expect(within(yml!).getByText('Changed')).toBeInTheDocument();
  expect(within(yml!).getByText('bbbbbbbbbbbb…')).toBeInTheDocument();
  expect(within(key!).getByText('Missing')).toBeInTheDocument();
  await user.click(within(screen.getByRole('region', { name: 'Deployment of api' })).getByRole('button', { name: 'Redeploy' }));
  await waitFor(() => expect(calls).toEqual(['redeploy g-2']));
});

it('shows the agent error of a failed deployment and toggles rows through the URL', async () => {
  const { user, router } = renderRoute('/o/acme/clients/cl-1/certificates');
  await findLoadedTable();
  await user.click(screen.getByRole('button', { name: 'Files for mail' }));
  expect(await screen.findByText('chown: unknown user nginx')).toBeInTheDocument();
  expect(router.state.location.search).toMatchObject({ open: 'g-3' });
  await user.click(screen.getByRole('button', { name: 'Files for mail' }));
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('open'));
});

it('removes a grant after the certificate name is typed', async () => {
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates');
  await findLoadedTable();
  await user.click(screen.getByRole('button', { name: 'Remove www' }));
  // I4: the confirm input gets focus on open, not the force switch above it
  // or the consequence's HelpTip, so typing the certificate name works at once.
  await waitFor(() => expect(screen.getByLabelText(/to confirm/)).toHaveFocus());
  await user.type(screen.getByLabelText(/to confirm/), 'www');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove' }));
  await waitFor(() => expect(screen.queryByRole('link', { name: 'www' })).not.toBeInTheDocument());
  expect(calls).toEqual(['delete g-1']);
});

it('removes without waiting for the agent when the force switch is on', async () => {
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates');
  await findLoadedTable();
  await user.click(screen.getByRole('button', { name: 'Remove www' }));
  await user.click(screen.getByRole('switch', { name: 'Remove without waiting for the agent' }));
  await user.type(screen.getByLabelText(/to confirm/), 'www');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove' }));
  await waitFor(() => expect(calls).toEqual(['delete g-1 force']));
});

it('disables writes for a viewer', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  renderRoute('/o/acme/clients/cl-1/certificates');
  await findLoadedTable();
  expect(screen.getByRole('button', { name: 'Redeploy www' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Remove www' })).toBeDisabled();
});

it('explains disabled writes on a revoked client without blaming permissions', async () => {
  server.use(http.get(url('/orgs/org-1/clients/cl-1'), () => HttpResponse.json(makeClient({ status: 'revoked', connected: false, online: false }))));
  renderRoute('/o/acme/clients/cl-1/certificates');
  await findLoadedTable();
  const remove = screen.getByRole('button', { name: 'Remove www' });
  expect(remove).toBeDisabled();
  act(() => (remove.parentElement as HTMLElement).focus());
  expect(await screen.findByRole('tooltip')).toHaveTextContent('The client is revoked');
});

it('renders cards below md, with hooks and auto-remediate', async () => {
  stubViewport(false);
  renderRoute('/o/acme/clients/cl-1/certificates');
  const cards = await screen.findByRole('list', { name: 'Grants' });
  expect(screen.queryByRole('table')).not.toBeInTheDocument();
  const wwwCard = within(cards).getByRole('link', { name: 'www' }).closest('li')!;
  expect(wwwCard).toHaveTextContent('1 hooks');
  expect(wwwCard).toHaveTextContent('Auto-remediate On');
  expect(within(cards).getByRole('link', { name: 'api' }).closest('li')!).toHaveTextContent('Drift');
});

it('says so when nothing is granted', async () => {
  grants = [];
  renderRoute('/o/acme/clients/cl-1/certificates');
  expect(await screen.findByText('No certificates granted yet.')).toBeInTheDocument();
});

it('shows skeleton rows while grants load', async () => {
  server.use(
    http.get(url('/orgs/org-1/clients/cl-1/grants'), async () => {
      await new Promise((r) => setTimeout(r, 30));
      return HttpResponse.json({ items: grants });
    }),
  );
  renderRoute('/o/acme/clients/cl-1/certificates');
  const table = await screen.findByRole('table', { name: 'Grants' });
  expect(table).toHaveAttribute('aria-busy', 'true');
  await screen.findByRole('link', { name: 'www' });
});

it('only disables the row being redeployed', async () => {
  server.use(
    http.post(url('/orgs/org-1/grants/:id/redeploy'), async ({ params }) => {
      calls.push(`redeploy ${params.id}`);
      await new Promise((r) => setTimeout(r, 30));
      return HttpResponse.json(grants.find((g) => g.id === params.id));
    }),
  );
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates');
  await findLoadedTable();
  await user.click(screen.getByRole('button', { name: 'Redeploy www' }));
  expect(screen.getByRole('button', { name: 'Redeploy www' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Redeploy api' })).toBeEnabled();
  await waitFor(() => expect(screen.getByRole('button', { name: 'Redeploy www' })).toBeEnabled());
});

it('shows a toast when redeploy fails', async () => {
  server.use(http.post(url('/orgs/org-1/grants/:id/redeploy'), () => problem(500, 'agent unreachable')));
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates');
  await findLoadedTable();
  await user.click(screen.getByRole('button', { name: 'Redeploy www' }));
  expect(await screen.findByText('agent unreachable')).toBeInTheDocument();
});

// Task 8 (Review Focus: nullable grant fields never crash the client grants
// tab): Grant.clientId/clientName/deployment are nullable for a server grant
// (5a-facts.md); this endpoint is client-scoped and never actually returns
// one today, but the table must still render a runsOn:'server' row safely
// rather than dereferencing `deployment!`.
it('renders a server grant row with a Server chip and its own deployment chip, without crashing', async () => {
  grants = [{ ...grantServer, certificateName: 'api', deployTargetId: targetVaultKv.id }];
  server.use(http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [targetVaultKv] })));
  renderRoute('/o/acme/clients/cl-1/certificates');
  await findLoadedTable();
  const row = rowOf('api');
  expect(within(row).getByText('Server')).toBeInTheDocument();
  expect(within(row).getByText(targetVaultKv.name)).toBeInTheDocument();
  expect(within(row).getByText('Deployed')).toBeInTheDocument();
});

// ServerDeploymentChip: a failed status shows the server's own lastError as
// its tooltip (UI conventions table), separate from the withHelp icon's
// generic serverDeployment.status explanation.
it('shows a failed server grant\'s lastError as the chip\'s own tooltip', async () => {
  grants = [{ ...grantServer, certificateName: 'api', deployTargetId: targetVaultKv.id, serverDeployment: { status: 'failed', versionId: 'v-1', lastError: 'vault: permission denied', deployedAt: null, updatedAt: iso(0) } }];
  server.use(http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [targetVaultKv] })));
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates');
  await findLoadedTable();
  const row = rowOf('api');
  const chip = within(row).getByText('Failed');
  await user.hover(chip);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('vault: permission denied');
});
