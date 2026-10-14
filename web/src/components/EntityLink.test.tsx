import { createMemoryHistory } from '@tanstack/react-router';
import { expect, it } from 'vitest';
import { makeQueryClient } from '@/lib/queryClient';
import { createAppRouter } from '@/router';
import { entityTarget, grantTarget, RESOURCE_KIND, type EntityKind, type Target } from './EntityLink';

const router = createAppRouter(makeQueryClient({ test: true }), createMemoryHistory({ initialEntries: ['/'] }));
const href = (t: Target) => router.buildLocation(t as never).href;

it('maps every kind to its route and search params', () => {
  const rows: [Exclude<EntityKind, 'grant'>, string][] = [
    ['certificate', '/o/acme/certificates/x-1/overview'],
    ['client', '/o/acme/clients/x-1/certificates'],
    ['ca', '/o/acme/issuers/cas/x-1/overview'],
    ['acmeAccount', '/o/acme/issuers/accounts'],
    ['dnsCredential', '/o/acme/issuers/dns?edit=x-1'],
    ['target', '/o/acme/delivery/targets/x-1/overview'],
    ['layout', '/o/acme/delivery/layouts/x-1/edit'],
    ['action', '/o/acme/delivery/actions?tab=actions&edit=x-1'],
    ['actionGroup', '/o/acme/delivery/actions?tab=groups&edit=x-1'],
    ['deployCredential', '/o/acme/delivery/credentials?edit=x-1'],
    ['monitor', '/o/acme/alerts/monitors/x-1/edit'],
    ['channel', '/o/acme/alerts/channels?edit=x-1'],
    ['user', '/settings/access?tab=users'],
    ['apiKey', '/settings/access?tab=keys'],
    ['site', '/settings/general?org=acme&site=x-1'],
  ];
  for (const [kind, want] of rows) expect(href(entityTarget(kind, 'x-1', 'acme'))).toBe(want);
});

it('sends a grant to its target or client, and nowhere without either', () => {
  const base = { id: 'g-1', runsOn: 'server' as const, deployTargetId: 't-1', clientId: null };
  expect(href(grantTarget(base, 'acme')!)).toBe('/o/acme/delivery/targets/t-1/grants?open=g-1');
  expect(href(grantTarget({ ...base, runsOn: 'agent', deployTargetId: null, clientId: 'c-1' }, 'acme')!)).toBe('/o/acme/clients/c-1/certificates?open=g-1');
  expect(grantTarget({ ...base, deployTargetId: null }, 'acme')).toBeNull();
});

it('covers the audit resource types that have a page', () => {
  expect(RESOURCE_KIND.deploy_target).toBe('target');
  expect(RESOURCE_KIND.api_key).toBe('apiKey');
  expect(RESOURCE_KIND.settings).toBeUndefined();
});
