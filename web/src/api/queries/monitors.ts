import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { POLL } from '@/lib/polling';
import { api, call } from '../client';
import type { Monitor, MonitorInput } from '../types';

export const monitorsQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['monitors', orgId],
    queryFn: () => call(api.GET('/orgs/{orgId}/monitors', { params: { path: { orgId } } })),
    refetchInterval: POLL.list,
  });

export function useCreateMonitor(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: MonitorInput) => call(api.POST('/orgs/{orgId}/monitors', { params: { path: { orgId } }, body })),
    meta: { silent: true, success: 'Monitor created' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['monitors', orgId] }),
  });
}

// No fixed success message here (unlike useCreateMonitor): Task 4's
// MonitorSheet shows its own toast on save — "Monitor saved" normally, or
// "Monitor saved; state resets to Unknown" when host, port, SNI or the
// expected certificate changed — so the mutation itself stays silent on
// success and lets the caller pick the wording.
export function useUpdateMonitor(orgId: string, id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: MonitorInput) => call(api.PATCH('/orgs/{orgId}/monitors/{id}', { params: { path: { orgId, id } }, body })),
    meta: { silent: true },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['monitors', orgId] }),
  });
}

export function useDeleteMonitor(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/monitors/{id}', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Monitor deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['monitors', orgId] }),
  });
}

// checkMonitor's inline result replaces the one row in the cached list
// (setQueryData) instead of invalidating the whole list — the review focus
// on polling/refetch cost applies here too: a 15 s-bound inline check has no
// reason to force a full list refetch.
export function useCheckMonitor(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.POST('/orgs/{orgId}/monitors/{id}/check', { params: { path: { orgId, id } } })),
    meta: { silent: true },
    onSuccess: (monitor: Monitor) =>
      qc.setQueryData<Monitor[]>(['monitors', orgId], (old) => old?.map((m) => (m.id === monitor.id ? monitor : m))),
  });
}
