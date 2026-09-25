import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';

// Orgs list and CRUD (Settings → General).
export const orgsQuery = queryOptions({
  queryKey: ['orgs'],
  queryFn: async () => (await call(api.GET('/orgs'))).items,
});

export function useSaveOrg() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: { slug: string; name: string } }) =>
      id
        ? call(api.PATCH('/orgs/{orgId}', { params: { path: { orgId: id } }, body: { name: body.name } }))
        : call(api.POST('/orgs', { body })),
    meta: { silent: true, success: 'Organization saved' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['orgs'] }),
  });
}

export function useDeleteOrg() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}', { params: { path: { orgId: id } } })),
    meta: { silent: true, success: 'Organization deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['orgs'] }),
  });
}
