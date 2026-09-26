import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import type { CertificateDeployment } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, makeCert, makeDeployment, makeSite, meWith, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let rows: CertificateDeployment[];
let redeployed: string[];

beforeEach(() => {
  redeployed = [];
  rows = [
    {
      grantId: 'g-1', clientId: 'cl-1', clientName: 'web-1', clientStatus: 'active', clientConnected: true, clientOnline: true, siteId: 's-1', delivery: 'push',
      layoutId: 'l-1', layoutName: 'nginx', deployTargetId: null, deployTargetName: null, deployment: makeDeployment(),
    },
    {
      grantId: 'g-2', clientId: 'cl-2', clientName: 'db-1', clientStatus: 'active', clientConnected: false, clientOnline: false, siteId: null, delivery: 'pull',
      layoutId: null, layoutName: null, deployTargetId: 't-1', deployTargetName: 'edge traefik',
      deployment: makeDeployment({ state: 'drift', installed: [{ path: '/etc/ssl/www.pem', sha256: 'bb'.repeat(32) }] }),
    },
  ];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(makeCert())),
    http.get(url('/orgs/org-1/certificates/c-1/deployments'), () => HttpResponse.json({ items: rows })),
    http.get(url('/orgs/org-1/sites'), () => HttpResponse.json({ items: [makeSite({ id: 's-1', name: 'Rack A' })] })),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.post(url('/orgs/org-1/grants/:id/redeploy'), ({ params }) => {
      redeployed.push(params.id as string);
      return HttpResponse.json({});
    }),
  );
});

it('lists every client holding the certificate with state and installed files', async () => {
  renderRoute('/o/acme/certificates/c-1/deployments');
  const list = await screen.findByRole('list', { name: 'Deployments' });
  const web = within(list).getByRole('link', { name: 'web-1' }).closest('li')!;
  for (const text of ['Online', 'Rack A', 'Push', 'Deployed', 'Current version · 1/1 files match']) expect(within(web).getByText(text)).toBeInTheDocument();
  const db = within(list).getByRole('link', { name: 'db-1' });
  expect(db).toHaveAttribute('href', '/o/acme/clients/cl-2/certificates?open=g-2');
  for (const text of ['Offline', 'Pull', 'Drift', 'Current version · 0/1 files match']) expect(within(db.closest('li')!).getByText(text)).toBeInTheDocument();
});

it('shows the layout and deploy target of each grant, linking to Delivery', async () => {
  renderRoute('/o/acme/certificates/c-1/deployments');
  const list = await screen.findByRole('list', { name: 'Deployments' });
  const web = within(list).getByRole('link', { name: 'web-1' }).closest('li')!;
  expect(within(web).getByRole('link', { name: 'nginx' })).toHaveAttribute('href', '/o/acme/delivery/layouts?edit=l-1');
  expect(within(web).queryByRole('link', { name: 'edge traefik' })).not.toBeInTheDocument();
  const db = within(list).getByRole('link', { name: 'db-1' }).closest('li')!;
  expect(within(db).getByRole('link', { name: 'edge traefik' })).toHaveAttribute('href', '/o/acme/delivery/targets?edit=t-1');
  expect(within(db).queryByRole('link', { name: 'nginx' })).not.toBeInTheDocument();
});

it('shows a pull client seen recently as Online', async () => {
  rows = [{ ...rows[1], clientOnline: true }];
  renderRoute('/o/acme/certificates/c-1/deployments');
  const list = await screen.findByRole('list', { name: 'Deployments' });
  expect(within(within(list).getByRole('link', { name: 'db-1' }).closest('li')!).getByText('Online')).toBeInTheDocument();
});

it('redeploys one row', async () => {
  const { user } = renderRoute('/o/acme/certificates/c-1/deployments');
  const list = await screen.findByRole('list', { name: 'Deployments' });
  await user.click(within(within(list).getByRole('link', { name: 'db-1' }).closest('li')!).getByRole('button', { name: 'Redeploy' }));
  await waitFor(() => expect(redeployed).toEqual(['g-2']));
});

it('points at Clients when nothing holds it', async () => {
  rows = [];
  renderRoute('/o/acme/certificates/c-1/deployments');
  expect(await screen.findByText('Not granted to any client yet.')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Open clients' })).toHaveAttribute('href', '/o/acme/clients');
});

it('disables Redeploy for a viewer', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: 'org-1' }]))));
  renderRoute('/o/acme/certificates/c-1/deployments');
  const list = await screen.findByRole('list', { name: 'Deployments' });
  for (const button of within(list).getAllByRole('button', { name: 'Redeploy' })) expect(button).toBeDisabled();
});

it('shows Older version when the installed version is not the certificate\'s current one, and No version yet before a first issue', async () => {
  rows = [
    { ...rows[0], deployment: makeDeployment({ versionId: 'v-0' }) },
    { ...rows[1], deployment: makeDeployment({ state: 'pending', versionId: null, installed: [], reportedAt: null }) },
  ];
  renderRoute('/o/acme/certificates/c-1/deployments');
  const list = await screen.findByRole('list', { name: 'Deployments' });
  expect(within(within(list).getByRole('link', { name: 'web-1' }).closest('li')!).getByText(/^Older version/)).toBeInTheDocument();
  expect(within(within(list).getByRole('link', { name: 'db-1' }).closest('li')!).getByText('No version yet')).toBeInTheDocument();
});
