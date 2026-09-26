import { http, HttpResponse } from 'msw';
import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { Grant } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, makeClient, makeDeployment, makeGrant, makeHook, makeLayout, makeTarget, meWith, org, url } from '@/test/fixtures';
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
    http.delete(url('/orgs/org-1/grants/:id'), ({ params }) => {
      calls.push(`delete ${params.id}`);
      grants = grants.filter((g) => g.id !== params.id);
      return new HttpResponse(null, { status: 204 });
    }),
  );
});

const rowOf = (name: string) => screen.getByRole('link', { name }).closest('tr')!;

it('is the default tab and lists grants with delivery, layout, target, hooks and state', async () => {
  const { router } = renderRoute('/o/acme/clients/cl-1');
  await screen.findByRole('table', { name: 'Grants' });
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
  await screen.findByRole('table', { name: 'Grants' });
  await user.click(screen.getByRole('button', { name: 'Files for mail' }));
  expect(await screen.findByText('chown: unknown user nginx')).toBeInTheDocument();
  expect(router.state.location.search).toMatchObject({ open: 'g-3' });
  await user.click(screen.getByRole('button', { name: 'Files for mail' }));
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('open'));
});

it('removes a grant after the certificate name is typed', async () => {
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates');
  await screen.findByRole('table', { name: 'Grants' });
  await user.click(screen.getByRole('button', { name: 'Remove www' }));
  await user.type(screen.getByLabelText(/to confirm/), 'www');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove' }));
  await waitFor(() => expect(screen.queryByRole('link', { name: 'www' })).not.toBeInTheDocument());
  expect(calls).toEqual(['delete g-1']);
});

it('disables writes for a viewer', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  renderRoute('/o/acme/clients/cl-1/certificates');
  await screen.findByRole('table', { name: 'Grants' });
  expect(screen.getByRole('button', { name: 'Redeploy www' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Remove www' })).toBeDisabled();
});

it('explains disabled writes on a revoked client without blaming permissions', async () => {
  server.use(http.get(url('/orgs/org-1/clients/cl-1'), () => HttpResponse.json(makeClient({ status: 'revoked', connected: false, online: false }))));
  renderRoute('/o/acme/clients/cl-1/certificates');
  await screen.findByRole('table', { name: 'Grants' });
  const remove = screen.getByRole('button', { name: 'Remove www' });
  expect(remove).toBeDisabled();
  act(() => (remove.parentElement as HTMLElement).focus());
  expect(await screen.findByRole('tooltip')).toHaveTextContent('The client is revoked');
});

it('renders cards below md', async () => {
  stubViewport(false);
  renderRoute('/o/acme/clients/cl-1/certificates');
  const cards = await screen.findByRole('list', { name: 'Grants' });
  expect(screen.queryByRole('table')).not.toBeInTheDocument();
  expect(within(cards).getByRole('link', { name: 'api' }).closest('li')!).toHaveTextContent('Drift');
});

it('says so when nothing is granted', async () => {
  grants = [];
  renderRoute('/o/acme/clients/cl-1/certificates');
  expect(await screen.findByText('No certificates granted yet.')).toBeInTheDocument();
});
