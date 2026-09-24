import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';
import type { CAInput } from '../types';

export const casQuery = (orgId: string) =>
  queryOptions({ queryKey: ['cas', orgId], queryFn: () => call(api.GET('/orgs/{orgId}/cas', { params: { path: { orgId } } })) });

export const presetsQuery = queryOptions({
  queryKey: ['ca-presets'],
  queryFn: () => call(api.GET('/meta/ca-presets')),
  staleTime: Infinity,
});

export function useSaveCa(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: CAInput }) =>
      id
        ? call(api.PUT('/orgs/{orgId}/cas/{id}', { params: { path: { orgId, id } }, body }))
        : call(api.POST('/orgs/{orgId}/cas', { params: { path: { orgId } }, body })),
    // Fix round 1 (#6): 422/409 already show inline in CaSheet; a toast too
    // would be redundant (and, for a 422 mapped to a field, out of context).
    meta: { silent: true, success: 'CA saved' },
    // Fix round 1 (Task 9 review, Important — same exposure applies here):
    // the mutation's variables (the EAB HMAC) would otherwise sit in the
    // MutationCache for the default 5-minute gcTime.
    gcTime: 0,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cas', orgId] }),
  });
}

export function useDeleteCa(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/cas/{id}', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'CA deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cas', orgId] }),
  });
}
