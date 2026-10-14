import { http, HttpResponse } from 'msw';
import { screen, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { account, authHandlers, ca, makeAction, makeActionGroup, makeCert, makeClient, makeGrant, makeTarget, meWith, traefikSchema, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

it('links the certificate header CA and ACME account to their pages', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/certificates/c-1'), () => HttpResponse.json(makeCert({ effective: { caId: { value: 'ca-1', source: 'org' }, accountId: { value: 'acc-1', source: 'org' } } }))),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([ca])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([account])),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json({})),
  );
  renderRoute('/o/acme/certificates/c-1/overview');
  expect((await screen.findAllByRole('link', { name: "Let's Encrypt" }))[0]).toHaveAttribute('href', '/o/acme/issuers/cas/ca-1/overview');
  expect(screen.getAllByRole('link', { name: 'ops@example.com' })[0]).toHaveAttribute('href', '/o/acme/issuers/accounts');
});

it('links each action of a group to its sheet', async () => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/actions'), () => HttpResponse.json({ items: [makeAction({ id: 'a-1' }), makeAction({ id: 'a-2', name: 'verify site' })] })),
    http.get(url('/orgs/org-1/action-groups'), () => HttpResponse.json({ items: [makeActionGroup()] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [] })),
  );
  renderRoute('/o/acme/delivery/actions?tab=groups');
  expect(await screen.findByRole('link', { name: 'verify site' })).toHaveAttribute('href', '/o/acme/delivery/actions?tab=actions&edit=a-2');
});

it('links a target row to its deploy credential', async () => {
  vi.stubGlobal('matchMedia', (query: string) => ({ matches: query === '(min-width: 768px)', media: query, addEventListener: () => {}, removeEventListener: () => {} }));
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema], deployCredentials: [], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [makeTarget({ credentialId: 'dc-1' })] })),
    http.get(url('/orgs/org-1/deploy-credentials'), () => HttpResponse.json([{ id: 'dc-1', name: 'kvm login' }])),
  );
  renderRoute('/o/acme/delivery/targets');
  expect(await screen.findByRole('link', { name: 'kvm login' })).toHaveAttribute('href', '/o/acme/delivery/credentials?edit=dc-1');
});

it('opens a click popover of a grant\'s steps, each linking to its action', async () => {
  vi.stubGlobal('matchMedia', (query: string) => ({ matches: query === '(min-width: 768px)', media: query, addEventListener: () => {}, removeEventListener: () => {} }));
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/clients/cl-1'), () => HttpResponse.json(makeClient())),
    http.get(url('/orgs/org-1/clients/cl-1/grants'), () => HttpResponse.json({ items: [makeGrant({ steps: [{ action: 'a-1' }, { group: 'ag-1' }] })] })),
    http.get(url('/orgs/org-1/actions'), () => HttpResponse.json({ items: [makeAction({ id: 'a-1' })] })),
    http.get(url('/orgs/org-1/action-groups'), () => HttpResponse.json({ items: [makeActionGroup()] })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'admin', orgId: null }]))),
  );
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates');
  await user.click(await screen.findByRole('button', { name: '2' }));
  expect(await screen.findByRole('link', { name: 'reload nginx' })).toHaveAttribute('href', '/o/acme/delivery/actions?tab=actions&edit=a-1');
  expect(within(screen.getByRole('link', { name: 'web reload' }).closest('li')!).getByText('group')).toBeInTheDocument();
});
