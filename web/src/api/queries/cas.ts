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
// config.importKeyPem, a secret (global constraints, "Secrets") — the
// kind-aware CaSheet (task 2) calls this for every kind and invalidates
// ['cas', orgId] itself instead of going through the mutation cache, so the
// secret never sits in the MutationCache. Replaced useSaveCa below, which
// task 2 removed once CaSheet was its only caller.
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
    // silent (task 3, same precedent as useRotateAgentCA): fired from
    // ConfirmDestructive, whose own inline banner would otherwise duplicate
    // the global error toast a 422 already shows.
    meta: { silent: true, success: 'Issuing certificate rotated' },
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
