import { describe, expect, it } from 'vitest';
import type { MeBinding } from '@/api/types';
import { can, canAnywhere, canGrantScope, hasGlobalBinding, type Action } from './permissions';

const A = 'org-a';
const B = 'org-b';
const me = (...bindings: MeBinding[]) => ({ bindings, orgs: [{ id: A, slug: 'a', name: 'A' }, { id: B, slug: 'b', name: 'B' }] });

describe('can mirrors authz.Can', () => {
  const cases: [string, ReturnType<typeof me>, Action, string | null, boolean][] = [
    ['admin settings write', me({ role: 'admin', orgId: null }), 'settings:write', null, true],
    ['admin keys export in org', me({ role: 'admin', orgId: null }), 'keys:export', A, true],
    ['org-admin certs write own', me({ role: 'org-admin', orgId: A }), 'certs:write', A, true],
    ['org-admin certs write other', me({ role: 'org-admin', orgId: A }), 'certs:write', B, false],
    ['org-admin settings write', me({ role: 'org-admin', orgId: A }), 'settings:write', null, false],
    ['org-admin shared cas read', me({ role: 'org-admin', orgId: A }), 'cas:read', null, true],
    ['org-admin certs read global', me({ role: 'org-admin', orgId: A }), 'certs:read', null, false],
    ['org-admin users read shared', me({ role: 'org-admin', orgId: A }), 'users:read', null, true],
    ['org-admin users write', me({ role: 'org-admin', orgId: A }), 'users:write', null, false],
    ['org-admin bindings write global', me({ role: 'org-admin', orgId: A }), 'bindings:write', null, false],
    ['viewer audit', me({ role: 'viewer', orgId: A }), 'audit:read', A, false],
    ['viewer sites read', me({ role: 'viewer', orgId: A }), 'sites:read', A, true],
    ['auditor audit', me({ role: 'auditor', orgId: A }), 'audit:read', A, true],
    ['operator apikeys write', me({ role: 'operator', orgId: A }), 'apikeys:write', A, false],
    ['global viewer reads other org', me({ role: 'viewer', orgId: null }), 'certs:read', B, true],
    ['global viewer cannot write', me({ role: 'viewer', orgId: null }), 'certs:write', B, false],
    ['mixed: viewer A write', me({ role: 'viewer', orgId: A }, { role: 'operator', orgId: B }), 'certs:write', A, false],
    ['mixed: operator B write', me({ role: 'viewer', orgId: A }, { role: 'operator', orgId: B }), 'certs:write', B, true],
    ['no bindings', me(), 'orgs:read', null, false],
  ];
  it.each(cases)('%s', (_, m, action, org, want) => expect(can(m, action, org)).toBe(want));
});

it('knows when the All orgs view is available', () => {
  expect(hasGlobalBinding(me({ role: 'auditor', orgId: null }))).toBe(true);
  expect(hasGlobalBinding(me({ role: 'admin', orgId: A }))).toBe(false);
});

it('canAnywhere checks global and every visible org', () => {
  expect(canAnywhere(me({ role: 'auditor', orgId: B }), 'audit:read')).toBe(true);
  expect(canAnywhere(me({ role: 'viewer', orgId: A }), 'audit:read')).toBe(false);
});

it('canGrantScope intersects with the creator role', () => {
  const oa = me({ role: 'org-admin', orgId: A });
  expect(canGrantScope(oa, 'certs:read', A)).toBe(true);
  expect(canGrantScope(oa, 'admin', A)).toBe(false);
  expect(canGrantScope(oa, 'keys:export', A)).toBe(false);
  expect(canGrantScope(me({ role: 'admin', orgId: null }), 'admin', null)).toBe(true);
});
