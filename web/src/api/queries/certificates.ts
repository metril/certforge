import { infiniteQueryOptions, queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { filenameFrom, saveBlob } from '@/lib/download';
import { firstPagePoll, livePoll, POLL } from '@/lib/polling';
import { api, call } from '../client';
import { ApiError, errorMessage } from '../errors';
import type { Certificate, CertificateInput, CertificateUpload, CertificateVersionUpload, CertStatus, ExportRequest, RevocationReason } from '../types';

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
      void qc.invalidateQueries({ queryKey: ['certs', orgId] });
      void qc.invalidateQueries({ queryKey: ['certs', orgId, 'one', id] });
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

/** The same walk for pickers: fetched when the picker mounts, never polled. */
export const allCertificatesPickerQuery = (orgId: string) =>
  queryOptions({ queryKey: ['certs', orgId, 'all'], queryFn: () => fetchAllCertificates(orgId) });

/** The Overview's server-side summary (counts plus the briefs that need a look)
 * for one org, or for every readable org when orgId is 'all'. */
export const certificateOverviewQuery = (orgId: string | 'all') =>
  queryOptions({
    queryKey: ['certs', orgId, 'overview'],
    queryFn: () =>
      call(orgId === 'all' ? api.GET('/certificates/summary') : api.GET('/orgs/{orgId}/certificates/summary', { params: { path: { orgId } } })),
    refetchInterval: POLL.list,
  });

/** The command palette's server-side search: name, common name or SAN, first 20 by name. */
export const certificateSearchQuery = (orgId: string, q: string) =>
  queryOptions({
    queryKey: ['certs', orgId, 'search', q],
    queryFn: () => call(api.GET('/orgs/{orgId}/certificates', { params: { path: { orgId }, query: { q, sort: 'name', limit: 20 } } })),
    staleTime: 10_000,
  });

export type CertListQuery = { status?: CertStatus; q?: string; sort?: string };

export const certListQueryKey = (orgId: string, s: CertListQuery) => ['certs', orgId, 'list', s] as const;

export const certificatesInfinite = (orgId: string, s: CertListQuery) =>
  infiniteQueryOptions({
    queryKey: certListQueryKey(orgId, s),
    queryFn: ({ pageParam }) =>
      call(api.GET('/orgs/{orgId}/certificates', { params: { path: { orgId }, query: { status: s.status, q: s.q, sort: s.sort, limit: 100, cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    refetchInterval: firstPagePoll,
  });

/** All orgs (lib/org.ts's ALL_ORGS_SLUG) view: pages through every
 * certificate the caller can read across orgs. */
export async function fetchAllOrgsCertificates(): Promise<Certificate[]> {
  const out: Certificate[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await call(api.GET('/certificates', { params: { query: { limit: PAGE, cursor } } }));
    out.push(...page.items);
    if (!page.nextCursor) break;
    cursor = page.nextCursor;
  }
  return out;
}

export const allOrgsCertificatesQuery = queryOptions({
  queryKey: ['certs', 'all', 'every'],
  queryFn: fetchAllOrgsCertificates,
  refetchInterval: POLL.list,
});

export const allOrgsCertificatesListKey = (s: CertListQuery): readonly ['certs', string, 'list', CertListQuery] => [
  'certs',
  'all',
  'list',
  s,
];

export const allOrgsCertificatesInfinite = (s: CertListQuery) =>
  infiniteQueryOptions({
    queryKey: allOrgsCertificatesListKey(s),
    queryFn: ({ pageParam }) =>
      call(api.GET('/certificates', { params: { query: { status: s.status, q: s.q, sort: s.sort, limit: 100, cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    refetchInterval: firstPagePoll,
  });

export function plural(n: number, word: string): string {
  return n === 1 ? `1 ${word}` : `${n} ${word}s`;
}

// reason is the first failure's message (a 409 says what blocks the delete).
export type BulkResult = { ok: string[]; failed: string[]; reason?: string };

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
  readonly reason?: string;
  constructor(failed: string[], reason?: string) {
    super(`All ${plural(failed.length, 'certificate')} failed.`);
    this.name = 'BulkActionError';
    this.failed = failed;
    this.reason = reason;
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
  let reason: string | undefined;
  results.forEach((r, i) => {
    if (r.status === 'fulfilled') ok.push(ids[i]!);
    else {
      failed.push(ids[i]!);
      reason ??= errorMessage(r.reason);
    }
  });
  if (ok.length === 0 && failed.length > 0) throw new BulkActionError(failed, reason);
  return { ok, failed, reason };
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

export const attemptsQuery = (orgId: string, id: string) =>
  queryOptions({
    queryKey: ['attempts', orgId, id],
    queryFn: () => call(api.GET('/orgs/{orgId}/certificates/{id}/attempts', { params: { path: { orgId, id } } })),
    refetchInterval: (q) => livePoll(!!q.state.data?.some((a) => a.outcome === 'running')),
    staleTime: 0,
  });

// One attempt with its log: the list omits logs, so the viewer loads the log
// of the attempt it shows, tailing it at the live rate until the fetched copy
// itself says finished, so the last fetch holds the final log.
export const attemptQuery = (orgId: string, id: string, attemptId: string, running: boolean) =>
  queryOptions({
    queryKey: ['attempts', orgId, id, attemptId],
    queryFn: () => call(api.GET('/orgs/{orgId}/certificates/{id}/attempts/{attemptId}', { params: { path: { orgId, id, attemptId } } })),
    refetchInterval: (q) => ((q.state.data ? q.state.data.outcome === 'running' : running) ? POLL.live : false),
    staleTime: 0,
  });

export const manualDnsQuery = (orgId: string, id: string) =>
  queryOptions({
    queryKey: ['manual-dns', orgId, id],
    queryFn: async () => {
      try {
        return await call(api.GET('/orgs/{orgId}/certificates/{id}/manual-dns', { params: { path: { orgId, id } } }));
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) return [];
        throw e;
      }
    },
    refetchInterval: POLL.list,
  });

export const versionsQuery = (orgId: string, id: string) =>
  queryOptions({
    queryKey: ['versions', orgId, id],
    queryFn: () => call(api.GET('/orgs/{orgId}/certificates/{id}/versions', { params: { path: { orgId, id } } })),
  });

// Private CAs only (localca, vaultpki); 422 for an acme-issued version or one
// that was imported/uploaded rather than issued (Shared contracts,
// revokeCertificateVersion).
export function useRevokeVersion(orgId: string, certId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ vid, reason }: { vid: string; reason: RevocationReason }) =>
      call(api.POST('/orgs/{orgId}/certificates/{id}/versions/{vid}/revoke', { params: { path: { orgId, id: certId, vid } }, body: { reason } })),
    meta: { silent: true, success: 'Version revoked' },
    // Batch 2 review (Important): a successful revoke also bumps the CA's
    // own config.revokedCount server-side (Task 3's private CA detail), so
    // ['cas', orgId] needs refetching too, not only this certificate's own
    // versions.
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['versions', orgId, certId] });
      void qc.invalidateQueries({ queryKey: ['cas', orgId] });
    },
  });
}

// Parts the server can render (docs/certificates.md "Downloads"): `combined`
// is fullchain + key in one file. `key` and `combined` both need
// keys:export (DownloadSheet disables those chips without it).
export type PemPart = 'cert' | 'chain' | 'fullchain' | 'key' | 'combined';
// DER supports only cert, chain and key, one per file (fullchain/combined
// are 422 "not available as DER").
export type DerPart = 'cert' | 'chain' | 'key';
export type Part = PemPart | DerPart;
export type DownloadFormat = 'pem' | 'der';

export async function downloadVersion(
  orgId: string,
  id: string,
  vid: string,
  { format, parts }: { format: DownloadFormat; parts: Part[] },
  baseName: string,
): Promise<void> {
  const { data, error, response } = await api.GET('/orgs/{orgId}/certificates/{id}/versions/{vid}/download', {
    params: { path: { orgId, id, vid }, query: { format, parts: parts.join(',') } },
    parseAs: 'blob',
  });
  if (error !== undefined || !response.ok || !data) throw ApiError.from(response.status, error);
  const fallbackExt = parts.length > 1 ? 'zip' : format;
  saveBlob(data, filenameFrom(response, `${baseName}.${fallbackExt}`));
}

// Direct api.POST (not a hook): the export password never touches the
// mutation cache (global constraints, "Secrets").
export async function exportVersion(orgId: string, id: string, vid: string, body: ExportRequest, baseName: string): Promise<void> {
  const { data, error, response } = await api.POST('/orgs/{orgId}/certificates/{id}/versions/{vid}/export', {
    params: { path: { orgId, id, vid } },
    body,
    parseAs: 'blob',
  });
  if (error !== undefined || !response.ok || !data) throw ApiError.from(response.status, error);
  saveBlob(data, filenameFrom(response, `${baseName}.${body.format}`));
}

// gcTime: 0 — the mutation's variables (a certificate/private key) must not
// linger in the mutation cache once it settles.
export function useUploadCertificate(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CertificateUpload) => call(api.POST('/orgs/{orgId}/certificates/upload', { params: { path: { orgId } }, body })),
    meta: { silent: true },
    gcTime: 0,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['certs', orgId] }),
  });
}

export function useUploadVersion(orgId: string, id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CertificateVersionUpload) =>
      call(api.POST('/orgs/{orgId}/certificates/{id}/versions/upload', { params: { path: { orgId, id } }, body })),
    meta: { silent: true },
    gcTime: 0,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['certs', orgId] });
      void qc.invalidateQueries({ queryKey: ['versions', orgId, id] });
    },
  });
}

// Adaptation (ruling): a 409 (nothing waiting, or the records expired) is an
// expected outcome the card shows inline, not a toast — `meta.silent`
// suppresses the mutationCache's default error toast. `onSettled` (not just
// `onSuccess`) refetches both queries on a 409 too, since the confirm may
// have raced a fresh set of records/an attempt failure the card should pick
// up regardless of which side won.
export function useConfirmManualDns(orgId: string, id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => call(api.POST('/orgs/{orgId}/certificates/{id}/manual-dns/confirm', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Checking the records now' },
    onSettled: async () => {
      await qc.invalidateQueries({ queryKey: ['manual-dns', orgId, id] });
      await qc.invalidateQueries({ queryKey: ['attempts', orgId, id] });
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['certs', orgId] });
    },
  });
}
