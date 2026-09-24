import { infiniteQueryOptions, queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { livePoll, POLL } from '@/lib/polling';
import { api, call } from '../client';
import type { Certificate, CertificateInput, CertStatus } from '../types';

export const certificateQuery = (orgId: string, id: string) =>
  queryOptions({
    queryKey: ['certs', orgId, 'one', id],
    queryFn: () => call(api.GET('/orgs/{orgId}/certificates/{id}', { params: { path: { orgId, id } } })),
    refetchInterval: (q) => livePoll(q.state.data?.status === 'pending'),
    staleTime: 0,
  });

export function useCreateCertificate(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CertificateInput) => call(api.POST('/orgs/{orgId}/certificates', { params: { path: { orgId } }, body })),
    // The wizard maps a 422 back to the step that owns the named field and
    // shows the detail there, and any other failure as its own Review-step
    // banner (controller ruling) — a toast on top would be redundant, same
    // pattern as useSaveOrgDefaults/useSaveCa/useSaveCredential.
    meta: { silent: true },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['certs', orgId] }),
  });
}

// Adaptation (controller ruling, docs/design.md "Certificate create
// wizard"): PUT replaces a certificate's definition; the server queues a
// new issuance only when names changed (internal/api/certificates.go
// UpdateCertificate). Not in the Task 14 brief's code sample, which covers
// create only.
export function useUpdateCertificate(orgId: string, id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CertificateInput) => call(api.PUT('/orgs/{orgId}/certificates/{id}', { params: { path: { orgId, id } }, body })),
    meta: { silent: true },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['certs', orgId] });
      qc.invalidateQueries({ queryKey: ['certs', orgId, 'one', id] });
    },
  });
}

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

export function plural(n: number, word: string): string {
  return n === 1 ? `1 ${word}` : `${n} ${word}s`;
}

export type BulkResult = { ok: string[]; failed: string[] };

// Fix round 1 (review, Important): a total failure must reject the mutation
// (not just report `failed: ids.length`) so a caller like `ConfirmDestructive`
// — which only shows its inline error and stays open when `onConfirm` throws
// — actually does that instead of quietly closing. `BulkActionError` carries
// the failed ids so the caller can re-select them and name them in a toast;
// it's thrown only when nothing at all succeeded (a partial failure still
// resolves normally with both arrays, since some of the bulk action did go
// through).
export class BulkActionError extends Error {
  readonly failed: string[];
  constructor(failed: string[]) {
    super(`All ${plural(failed.length, 'certificate')} failed.`);
    this.name = 'BulkActionError';
    this.failed = failed;
  }
}

// Adaptation (preflight D15) + fix round 1: a plain `Promise.all` over
// per-id mutation calls means one rejection loses every other result and
// the caller never learns which ids actually went through.
// `Promise.allSettled` always resolves with a per-id outcome; the ids (not
// just counts) travel back so the caller can keep the failed rows selected
// and name them, and neither hook shows its own toast any more (see
// `BulkActionError`'s doc comment) — the caller has the certificate names,
// the hook only has ids.
async function settleBulk(ids: string[], run: (id: string) => Promise<unknown>): Promise<BulkResult> {
  const results = await Promise.allSettled(ids.map((id) => run(id)));
  const ok: string[] = [];
  const failed: string[] = [];
  results.forEach((r, i) => (r.status === 'fulfilled' ? ok : failed).push(ids[i]!));
  if (ok.length === 0 && failed.length > 0) throw new BulkActionError(failed);
  return { ok, failed };
}

export function useRenewCertificates(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (ids: string[]) =>
      settleBulk(ids, (id) => call(api.POST('/orgs/{orgId}/certificates/{id}/renew', { params: { path: { orgId, id } } }))),
    meta: { silent: true },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['certs', orgId] });
      await qc.invalidateQueries({ queryKey: ['attempts', orgId] });
    },
  });
}

export function useDeleteCertificates(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (ids: string[]) =>
      settleBulk(ids, (id) => call(api.DELETE('/orgs/{orgId}/certificates/{id}', { params: { path: { orgId, id } } }))),
    meta: { silent: true },
    onSuccess: ({ ok }) => {
      if (ok.length > 0) void qc.invalidateQueries({ queryKey: ['certs', orgId] });
    },
  });
}
