import { infiniteQueryOptions, queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { POLL } from '@/lib/polling';
import { api, call } from '../client';
import type { Certificate, CertStatus } from '../types';

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

export type CertListQuery = { status?: CertStatus; q?: string; sort?: string };

export const certListQueryKey = (orgId: string, s: CertListQuery) => ['certs', orgId, 'list', s] as const;

export const certificatesInfinite = (orgId: string, s: CertListQuery) =>
  infiniteQueryOptions({
    queryKey: certListQueryKey(orgId, s),
    queryFn: ({ pageParam }) =>
      call(api.GET('/orgs/{orgId}/certificates', { params: { path: { orgId }, query: { status: s.status, q: s.q, sort: s.sort, limit: 100, cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    refetchInterval: POLL.list,
  });

function plural(n: number, word: string): string {
  return n === 1 ? `1 ${word}` : `${n} ${word}s`;
}

// Adaptation (preflight D15): a plain `Promise.all` over per-id mutation
// calls means one rejection loses every other result and the caller never
// learns how many actually went through. `Promise.allSettled` always
// resolves with a per-id outcome so the toast can report partial success.
export function useRenewCertificates(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(
        ids.map((id) => call(api.POST('/orgs/{orgId}/certificates/{id}/renew', { params: { path: { orgId, id } } }))),
      );
      const ok = results.filter((r) => r.status === 'fulfilled').length;
      return { ok, failed: results.length - ok };
    },
    meta: { silent: true },
    onSuccess: async ({ ok, failed }) => {
      if (ok > 0) toast.success(`Renewal queued for ${plural(ok, 'certificate')}`);
      if (failed > 0) toast.error(`Failed to queue renewal for ${plural(failed, 'certificate')}`);
      await qc.invalidateQueries({ queryKey: ['certs', orgId] });
      await qc.invalidateQueries({ queryKey: ['attempts', orgId] });
    },
  });
}

export function useDeleteCertificates(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(
        ids.map((id) => call(api.DELETE('/orgs/{orgId}/certificates/{id}', { params: { path: { orgId, id } } }))),
      );
      const ok = results.filter((r) => r.status === 'fulfilled').length;
      return { ok, failed: results.length - ok };
    },
    meta: { silent: true },
    onSuccess: ({ ok, failed }) => {
      if (ok > 0) toast.success(`Deleted ${plural(ok, 'certificate')}`);
      if (failed > 0) toast.error(`Failed to delete ${plural(failed, 'certificate')}`);
      void qc.invalidateQueries({ queryKey: ['certs', orgId] });
    },
  });
}
