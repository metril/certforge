import { queryOptions, useMutation, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { api, call } from '../client';
import type { RoleBindingInput, SubjectType } from '../types';

export type BindingFilter = { orgId?: string; subjectType?: SubjectType };

export const bindingsQuery = (f: BindingFilter = {}) =>
  queryOptions({
    queryKey: ['bindings', f],
    queryFn: async () => (await call(api.GET('/role-bindings', { params: { query: f } }))).items,
  });

async function refresh(qc: QueryClient) {
  await qc.invalidateQueries({ queryKey: ['bindings'] });
  await qc.invalidateQueries({ queryKey: ['me'] });
}

export function useCreateBinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RoleBindingInput) => call(api.POST('/role-bindings', { body })),
    meta: { silent: true, success: 'Binding added' },
    onSuccess: () => refresh(qc),
  });
}

export function useDeleteBinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/role-bindings/{id}', { params: { path: { id } } })),
    meta: { silent: true, success: 'Binding removed' },
    onSuccess: () => refresh(qc),
  });
}
