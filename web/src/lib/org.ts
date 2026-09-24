import { useParams, useRouteContext } from '@tanstack/react-router';
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
