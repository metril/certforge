import type { ApiKeyScope, Me } from '@/api/types';

// Mirror of internal/authz/authz.go: AllActions, globalOnly, sharedRead,
// viewerActions and roleActions. Keep both in step.
export const ACTIONS = [
  'orgs:read', 'orgs:write', 'settings:read', 'settings:write', 'users:read', 'users:write',
  'cas:read', 'cas:write', 'accounts:read', 'accounts:write', 'dnscreds:read', 'dnscreds:write',
  'certs:read', 'certs:write', 'certs:issue', 'keys:export', 'clients:read', 'clients:write', 'audit:read',
  'sites:read', 'sites:write', 'bindings:read', 'bindings:write', 'apikeys:read', 'apikeys:write',
  'delivery:read', 'delivery:write', 'alerts:read', 'alerts:write',
] as const;
export type Action = (typeof ACTIONS)[number];

const GLOBAL_ONLY = new Set<Action>(['settings:write', 'orgs:write', 'cas:write', 'keys:export', 'users:write']);
const SHARED_READ = new Set<Action>(['orgs:read', 'settings:read', 'cas:read', 'users:read']);
const VIEWER: Action[] = ['orgs:read', 'settings:read', 'cas:read', 'accounts:read', 'dnscreds:read', 'certs:read', 'clients:read', 'sites:read', 'delivery:read', 'alerts:read'];

const ROLE_ACTIONS: Record<string, ReadonlySet<Action>> = {
  admin: new Set(ACTIONS),
  'org-admin': new Set(ACTIONS.filter((a) => !GLOBAL_ONLY.has(a))),
  operator: new Set<Action>([...VIEWER, 'accounts:write', 'dnscreds:write', 'certs:write', 'certs:issue', 'clients:write', 'delivery:write', 'alerts:write']),
  viewer: new Set(VIEWER),
  auditor: new Set<Action>([...VIEWER, 'audit:read']),
};

/** Mirrors authz.Can. orgId null or undefined means a global resource. */
export function can(me: Pick<Me, 'bindings'>, action: Action, orgId?: string | null): boolean {
  for (const b of me.bindings) {
    if (!ROLE_ACTIONS[b.role]?.has(action)) continue;
    if (b.orgId === null) return true;
    if (GLOBAL_ONLY.has(action)) continue;
    if (orgId == null) {
      if (SHARED_READ.has(action)) return true;
      continue;
    }
    if (b.orgId === orgId) return true;
  }
  return false;
}

/** A global binding makes the read-only All orgs view available. */
export function hasGlobalBinding(me: Pick<Me, 'bindings'>): boolean {
  return me.bindings.some((b) => b.orgId === null);
}

/** True when action is allowed globally or in at least one visible org. */
export function canAnywhere(me: Pick<Me, 'bindings' | 'orgs'>, action: Action): boolean {
  return can(me, action, null) || me.orgs.some((o) => can(me, action, o.id));
}

/** A global (org-less) admin binding — gates allOrgs channel writes and the
 * all-orgs-channel affordance, distinct from any single org's admin. */
export function isGlobalAdmin(me: Pick<Me, 'bindings'>): boolean {
  return me.bindings.some((b) => b.role === 'admin' && b.orgId === null);
}

export const API_KEY_SCOPES: ApiKeyScope[] = ['certs:read', 'certs:write', 'certs:issue', 'keys:export', 'clients:read', 'clients:write', 'delivery:read', 'delivery:write', 'admin'];

// Mirror of authz.ScopeGrant.
const SCOPE_GRANT: Record<ApiKeyScope, Action> = {
  'certs:read': 'certs:read', 'certs:write': 'certs:write', 'certs:issue': 'certs:issue',
  'keys:export': 'keys:export', 'clients:read': 'clients:read', 'clients:write': 'clients:write',
  'delivery:read': 'delivery:read', 'delivery:write': 'delivery:write',
  'alerts:read': 'alerts:read', 'alerts:write': 'alerts:write', admin: 'settings:write',
};

/** Whether the server would keep scope on a key the user creates in orgId. */
export function canGrantScope(me: Pick<Me, 'bindings'>, scope: ApiKeyScope, orgId: string | null): boolean {
  return can(me, SCOPE_GRANT[scope], orgId);
}
