import type { Me } from '@/api/types';

export type Permission = 'certs:write' | 'certs:issue' | 'keys:export';

// Mirror of the server's role table (spec: Auth and authorization). keys:export is admin-only by default.
const ROLE_PERMS: Record<string, Permission[]> = {
  admin: ['certs:write', 'certs:issue', 'keys:export'],
  'org-admin': ['certs:write', 'certs:issue'],
  operator: ['certs:write', 'certs:issue'],
  viewer: [],
  auditor: [],
};

export function can(me: Pick<Me, 'roles'>, p: Permission): boolean {
  return me.roles.some((r) => ROLE_PERMS[r]?.includes(p));
}
