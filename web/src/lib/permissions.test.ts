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

// Fix round 1 (review, Important #1): an independent matrix, transcribed by
// hand straight from internal/authz/authz.go — AllActions, globalOnly,
// sharedRead, viewerActions, roleActions — not derived from permissions.ts's
// own ROLE_ACTIONS/GLOBAL_ONLY/SHARED_READ/VIEWER, so this catches a drift
// between the two independently of whichever one an edit changed.
describe('full role x action x scope matrix (hand-transcribed from authz.go)', () => {
  // authz.AllActions, in the order authz.go declares it.
  const ALL_ACTIONS: Action[] = [
    'orgs:read', 'orgs:write', 'settings:read', 'settings:write',
    'users:read', 'users:write', 'cas:read', 'cas:write',
    'accounts:read', 'accounts:write', 'dnscreds:read', 'dnscreds:write',
    'certs:read', 'certs:write', 'certs:issue', 'keys:export',
    'clients:read', 'clients:write', 'audit:read',
    'sites:read', 'sites:write', 'bindings:read', 'bindings:write',
    'apikeys:read', 'apikeys:write',
    'delivery:read', 'delivery:write',
  ];

  // authz.globalOnly: only ever granted through a global (nil-org) binding.
  const GLOBAL_ONLY: Action[] = ['settings:write', 'orgs:write', 'cas:write', 'keys:export', 'users:write'];

  // authz.sharedRead: an org-scoped binding also grants these against a nil
  // (global-resource) query orgId.
  const SHARED_READ: Action[] = ['orgs:read', 'settings:read', 'cas:read', 'users:read'];

  // authz.viewerActions.
  const VIEWER_ACTIONS: Action[] = ['orgs:read', 'settings:read', 'cas:read', 'accounts:read', 'dnscreds:read', 'certs:read', 'clients:read', 'sites:read', 'delivery:read'];

  // authz.roleActions: each role's action set, transcribed independently.
  const ROLE_SETS: Record<string, Action[]> = {
    admin: ALL_ACTIONS,
    'org-admin': ALL_ACTIONS.filter((a) => !GLOBAL_ONLY.includes(a)),
    operator: [...VIEWER_ACTIONS, 'accounts:write', 'dnscreds:write', 'certs:write', 'certs:issue', 'clients:write', 'delivery:write'],
    viewer: VIEWER_ACTIONS,
    auditor: [...VIEWER_ACTIONS, 'audit:read'],
  };

  const ROLES = ['admin', 'org-admin', 'operator', 'viewer', 'auditor'] as const;

  // authz.bindingsAllow, restated directly against the hand-transcribed
  // tables above (not calling into permissions.ts's can()).
  function expected(role: string, action: Action, bindingOrgId: string | null, queryOrgId: string | null | undefined): boolean {
    if (!ROLE_SETS[role]?.includes(action)) return false;
    if (bindingOrgId === null) return true; // a global binding always grants a held action
    if (GLOBAL_ONLY.includes(action)) return false; // needs a global binding, and this one isn't
    if (queryOrgId == null) return SHARED_READ.includes(action); // global-resource query
    return bindingOrgId === queryOrgId;
  }

  type Scenario = { name: string; bindingOrgId: string | null; queryOrgId: string | null | undefined };
  const SCENARIOS: Scenario[] = [
    { name: 'global binding', bindingOrgId: null, queryOrgId: A },
    { name: 'binding in the same org', bindingOrgId: A, queryOrgId: A },
    { name: 'binding in another org', bindingOrgId: A, queryOrgId: B },
    { name: 'orgId null', bindingOrgId: A, queryOrgId: null },
    { name: 'orgId undefined', bindingOrgId: A, queryOrgId: undefined },
  ];

  for (const role of ROLES) {
    for (const action of ALL_ACTIONS) {
      for (const scenario of SCENARIOS) {
        const want = expected(role, action, scenario.bindingOrgId, scenario.queryOrgId);
        it(`${role} / ${action} / ${scenario.name} -> ${want}`, () => {
          const m = me({ role: role as MeBinding['role'], orgId: scenario.bindingOrgId });
          expect(can(m, action, scenario.queryOrgId)).toBe(want);
        });
      }
    }
  }

  it('an unknown role grants nothing', () => {
    const m = { bindings: [{ role: 'not-a-role', orgId: null }] as unknown as MeBinding[], orgs: [{ id: A, slug: 'a', name: 'A' }] };
    for (const action of ALL_ACTIONS) expect(can(m, action, A)).toBe(false);
    expect(can(m, 'orgs:read', null)).toBe(false);
  });
});
