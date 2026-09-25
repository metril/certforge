import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';

export const sitesQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['sites', orgId],
    queryFn: async () => (await call(api.GET('/orgs/{orgId}/sites', { params: { path: { orgId } } }))).items,
  });

export function useCreateSite(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => call(api.POST('/orgs/{orgId}/sites', { params: { path: { orgId } }, body: { name } })),
    meta: { silent: true, success: 'Site added' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sites', orgId] }),
  });
}

export function useUpdateSite(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) =>
      call(api.PATCH('/orgs/{orgId}/sites/{id}', { params: { path: { orgId, id } }, body: { name } })),
    meta: { silent: true, success: 'Site renamed' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sites', orgId] }),
  });
}

export function useDeleteSite(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/sites/{id}', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Site deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sites', orgId] }),
  });
}
