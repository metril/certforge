import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';
import type { DeployTargetInput, HookInput, LayoutInput } from '../types';
import { invalidateGrants } from './grants';

export const layoutsQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['layouts', orgId],
    queryFn: async () => (await call(api.GET('/orgs/{orgId}/layouts', { params: { path: { orgId } } }))).items,
  });

export function useSaveLayout(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: LayoutInput }) =>
      id
        ? call(api.PATCH('/orgs/{orgId}/layouts/{id}', { params: { path: { orgId, id } }, body }))
        : call(api.POST('/orgs/{orgId}/layouts', { params: { path: { orgId } }, body })),
    meta: { silent: true, success: 'Layout saved' },
    // A layout change re-renders every grant using it (new revision).
    onSuccess: () => Promise.all([qc.invalidateQueries({ queryKey: ['layouts', orgId] }), invalidateGrants(qc, orgId)]),
    // B3: LayoutInput.body can carry a plaintext export password. Once the
    // mutation settles and nothing observes it any more, it must not linger
    // in the mutation cache holding that password — gcTime 0 removes it as
    // soon as the sheet (its only observer) unmounts.
    gcTime: 0,
  });
}

export function useDeleteLayout(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/layouts/{id}', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Layout deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['layouts', orgId] }),
  });
}

export const deployTargetsQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['deploy-targets', orgId],
    queryFn: async () => (await call(api.GET('/orgs/{orgId}/deploy-targets', { params: { path: { orgId } } }))).items,
  });

export function useSaveDeployTarget(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: DeployTargetInput }) =>
      id
        ? call(api.PATCH('/orgs/{orgId}/deploy-targets/{id}', { params: { path: { orgId, id } }, body }))
        : call(api.POST('/orgs/{orgId}/deploy-targets', { params: { path: { orgId } }, body })),
    meta: { silent: true, success: 'Deploy target saved' },
    onSuccess: () => Promise.all([qc.invalidateQueries({ queryKey: ['deploy-targets', orgId] }), invalidateGrants(qc, orgId)]),
  });
}

export function useDeleteDeployTarget(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/deploy-targets/{id}', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Deploy target deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deploy-targets', orgId] }),
  });
}

export const hooksQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['hooks', orgId],
    queryFn: async () => (await call(api.GET('/orgs/{orgId}/hooks', { params: { path: { orgId } } }))).items,
  });

export function useSaveHook(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: HookInput }) =>
      id
        ? call(api.PATCH('/orgs/{orgId}/hooks/{id}', { params: { path: { orgId, id } }, body }))
        : call(api.POST('/orgs/{orgId}/hooks', { params: { path: { orgId } }, body })),
    meta: { silent: true, success: 'Hook saved' },
    onSuccess: () => Promise.all([qc.invalidateQueries({ queryKey: ['hooks', orgId] }), invalidateGrants(qc, orgId)]),
  });
}

export function useDeleteHook(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/hooks/{id}', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Hook deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hooks', orgId] }),
  });
}
