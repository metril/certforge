import { infiniteQueryOptions, queryOptions } from '@tanstack/react-query';
import { filenameFrom, saveBlob } from '@/lib/download';
import { POLL } from '@/lib/polling';
import { api, call } from '../client';
import { ApiError } from '../errors';

export type AuditFilter = {
  from?: string;
  to?: string;
  actor?: string;
  action?: string;
  resourceType?: string;
  resourceId?: string;
  orgId?: string;
  q?: string;
};

export const auditInfinite = (f: AuditFilter) =>
  infiniteQueryOptions({
    queryKey: ['audit', f],
    queryFn: ({ pageParam }) => call(api.GET('/audit', { params: { query: { ...f, limit: 100, cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    refetchInterval: POLL.list,
  });

export const recentActivityQuery = (orgId?: string) =>
  queryOptions({
    queryKey: ['audit', { orgId, limit: 20 }],
    queryFn: async () => (await call(api.GET('/audit', { params: { query: { orgId, limit: 20 } } }))).items,
    refetchInterval: POLL.list,
  });

export const auditVerifyQuery = queryOptions({
  queryKey: ['audit-verify'],
  queryFn: () => call(api.GET('/audit/verify')),
  staleTime: 60_000,
  refetchInterval: 60_000,
});

/** Fetches one event directly, for a deep link (`?event=<id>`) that opens
 * the sheet even when the event isn't in a currently loaded page. */
export const auditEventQuery = (id: number) =>
  queryOptions({
    queryKey: ['audit', 'event', id],
    queryFn: () => call(api.GET('/audit/{id}', { params: { path: { id } } })),
    retry: false,
  });

export type ExportResult = {
  /** X-Audit-Truncated: the 100,000-row cap was hit; some events are missing. */
  truncated: boolean;
  /** The file's last line is a `#error,...` row: a query failed partway
   * through the stream, so the file is incomplete (internal/api's
   * writeAuditCSV never truncates silently). */
  incomplete: boolean;
};

/** Downloads the filtered events as CSV (the server audits the export). */
export async function exportAudit(f: AuditFilter): Promise<ExportResult> {
  const { data, error, response } = await api.GET('/audit/export', { params: { query: f }, parseAs: 'blob' });
  if (error !== undefined || !response.ok || !data) throw ApiError.from(response.status, error);
  const blob = data as Blob;
  saveBlob(blob, filenameFrom(response, 'audit.csv'));
  const text = await blob.text();
  const lines = text.split('\n').filter((l) => l.trim() !== '');
  const lastLine = lines[lines.length - 1] ?? '';
  return {
    truncated: response.headers.get('X-Audit-Truncated') === 'true',
    incomplete: lastLine.startsWith('#error,'),
  };
}
