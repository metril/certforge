import { queryOptions, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { livePoll } from '@/lib/polling';
import { api, call } from '../client';
import type { EnrollmentRequest } from '../types';

export const pendingEnrollmentsKey = (orgId: string) => ['enrollment-requests', orgId] as const;

/** Unexpired requests awaiting an administrator. 2 s while any is waiting, 30 s otherwise. */
export const pendingEnrollmentsQuery = (orgId: string) =>
  queryOptions({
    queryKey: pendingEnrollmentsKey(orgId),
    queryFn: async () => (await call(api.GET('/orgs/{orgId}/enrollment-requests', { params: { path: { orgId } } }))).items,
    refetchInterval: (q) => livePoll((q.state.data?.length ?? 0) > 0),
    staleTime: 0,
  });

/** The shared query behind the queue, the nav badge and the Enrol page: one
 * request per org. `enabled` is false without clients:write or in All orgs. */
export function usePendingApprovals(orgId: string, enabled: boolean): EnrollmentRequest[] {
  const q = useQuery({ ...pendingEnrollmentsQuery(orgId), enabled, retry: false });
  return enabled ? (q.data ?? []) : [];
}

function useInvalidate() {
  const qc = useQueryClient();
  return (orgId: string) =>
    Promise.all([
      qc.invalidateQueries({ queryKey: pendingEnrollmentsKey(orgId) }),
      qc.invalidateQueries({ queryKey: ['clients', orgId] }),
      qc.invalidateQueries({ queryKey: ['clients', 'all'] }),
    ]);
}

export function useApproveEnrollment(orgId: string) {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (id: string) => call(api.POST('/orgs/{orgId}/enrollment-requests/{id}/approve', { params: { path: { orgId, id } } })),
    meta: { silent: true },
    onSettled: () => invalidate(orgId),
  });
}

export function useRejectEnrollment(orgId: string) {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (id: string) => call(api.POST('/orgs/{orgId}/enrollment-requests/{id}/reject', { params: { path: { orgId, id } } })),
    meta: { silent: true },
    onSettled: () => invalidate(orgId),
  });
}
