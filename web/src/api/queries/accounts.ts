import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';

export const accountsQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['accounts', orgId],
    queryFn: () => call(api.GET('/orgs/{orgId}/acme-accounts', { params: { path: { orgId } } })),
  });

export function useCreateAccount(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { caId: string; email: string }) => call(api.POST('/orgs/{orgId}/acme-accounts', { params: { path: { orgId } }, body })),
    meta: { success: 'Account registered' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['accounts', orgId] }),
  });
}

export function useDeleteAccount(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/acme-accounts/{id}', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Account deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['accounts', orgId] }),
  });
}
