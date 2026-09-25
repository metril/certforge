import { redirect, useParams, useRouteContext } from '@tanstack/react-router';
import type { Me, Org } from '@/api/types';

export function useOrg(): Org {
  return useRouteContext({ from: '/_app/o/$org', select: (c) => c.org });
}

export function useMe(): Me {
  return useRouteContext({ from: '/_app', select: (c) => c.me });
}

// Resolves the org slug for chrome (Sidebar, AppShell) that renders on both
// org-scoped and org-less routes (e.g. /settings/*): the `org` route param
// when present, otherwise the user's first org.
export function useActiveOrgSlug(): string | undefined {
  const me = useMe();
  const params = useParams({ strict: false }) as { org?: string };
  return params.org ?? me.orgs[0]?.slug;
}

export const ALL_ORGS_SLUG = 'all';
export const ALL_ORGS: Org = { id: 'all', slug: ALL_ORGS_SLUG, name: 'All orgs' };

/** True on /o/all/..., the read-only cross-org view. */
export function useAllOrgs(): boolean {
  return useRouteContext({ from: '/_app/o/$org', select: (c) => c.allOrgs });
}

/** beforeLoad guard for routes that write or need one org. */
export function denyAllOrgs(ctx: { allOrgs: boolean }): void {
  if (ctx.allOrgs) throw redirect({ to: '/o/$org/overview', params: { org: ALL_ORGS_SLUG } });
}

/** Slug of the org a cross-org item belongs to. */
export function useOrgSlugOf(): (orgId?: string) => string {
  const me = useMe();
  return (orgId) => me.orgs.find((o) => o.id === orgId)?.slug ?? ALL_ORGS_SLUG;
}
