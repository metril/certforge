import { queryOptions } from '@tanstack/react-query';
import { POLL } from '@/lib/polling';
import { api, call } from '../client';
import type { Certificate } from '../types';

const PAGE = 200;
const MAX_PAGES = 50;

/** Pages through every certificate in the org (up to 50 x 200 = 10k). Kept
 * for later tasks (wizard duplicate-name checks, palette search); DNS
 * credentials render their own `usedBy` from the API instead of counting
 * client-side (preflight A14). */
export async function fetchAllCertificates(orgId: string): Promise<Certificate[]> {
  const out: Certificate[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await call(api.GET('/orgs/{orgId}/certificates', { params: { path: { orgId }, query: { limit: PAGE, cursor } } }));
    out.push(...page.items);
    if (!page.nextCursor) break;
    cursor = page.nextCursor;
  }
  return out;
}

export const allCertificatesQuery = (orgId: string) =>
  queryOptions({ queryKey: ['certs', orgId, 'all'], queryFn: () => fetchAllCertificates(orgId), refetchInterval: POLL.list });
