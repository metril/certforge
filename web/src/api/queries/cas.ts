import { queryOptions, useMutation, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { api, call } from '../client';
import type { CA, CAInput } from '../types';

export const casQuery = (orgId: string) =>
  queryOptions({ queryKey: ['cas', orgId], queryFn: () => call(api.GET('/orgs/{orgId}/cas', { params: { path: { orgId } } })) });

export const presetsQuery = queryOptions({
  queryKey: ['ca-presets'],
  queryFn: () => call(api.GET('/meta/ca-presets')),
  staleTime: Infinity,
});

// Direct call (not useMutation): a private CA's create/edit body can carry
// config.importKeyPem, a secret (global constraints, "Secrets") — Task 2's
// kind-aware CaSheet calls this and invalidates ['cas', orgId] itself
// instead of going through the mutation cache. Replaces useSaveCa below for
// that sheet; useSaveCa stays for now since it still backs the acme-only
// CaSheet until Task 2 rebuilds it.
export function saveCa(qc: QueryClient, orgId: string, body: CAInput, id?: string): Promise<CA> {
  return (
    id
      ? call(api.PUT('/orgs/{orgId}/cas/{id}', { params: { path: { orgId, id } }, body }))
      : call(api.POST('/orgs/{orgId}/cas', { params: { path: { orgId } }, body }))
  ).then((ca) => {
    void qc.invalidateQueries({ queryKey: ['cas', orgId] });
    return ca;
  });
}

export function rotateCa(orgId: string, id: string): Promise<CA> {
  return call(api.POST('/orgs/{orgId}/cas/{id}/rotate', { params: { path: { orgId, id } } }));
}

export function useRotateCa(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => rotateCa(orgId, id),
    meta: { success: 'CA rotated' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cas', orgId] }),
  });
}

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
