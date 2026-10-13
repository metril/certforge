import { infiniteQueryOptions, queryOptions, useMutation, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { firstPagePoll } from '@/lib/polling';
import { api, call } from '../client';
import type { Action, ActionGroupInput, ActionInput, DeployTarget, DeployTargetInput, LayoutInput } from '../types';
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

// `TargetSheet` calls these directly (not through a mutation) so a target
// secret never sits in TanStack Query's mutation cache — it invalidates
// itself only after mapping a secret error onto the form.
export function createDeployTarget(orgId: string, body: DeployTargetInput): Promise<DeployTarget> {
  return call(api.POST('/orgs/{orgId}/deploy-targets', { params: { path: { orgId } }, body }));
}

export function updateDeployTarget(orgId: string, id: string, body: DeployTargetInput): Promise<DeployTarget> {
  return call(api.PATCH('/orgs/{orgId}/deploy-targets/{id}', { params: { path: { orgId, id } }, body }));
}

export function useDeleteDeployTarget(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/deploy-targets/{id}', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Deploy target deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deploy-targets', orgId] }),
  });
}

export const actionsQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['actions', orgId],
    queryFn: async () => (await call(api.GET('/orgs/{orgId}/actions', { params: { path: { orgId } } }))).items,
  });

// Direct calls (like deploy targets): an action's config can carry a secret
// header, which must never sit in the mutation cache.
export function createAction(orgId: string, body: ActionInput): Promise<Action> {
  return call(api.POST('/orgs/{orgId}/actions', { params: { path: { orgId } }, body }));
}

export function updateAction(orgId: string, id: string, body: ActionInput): Promise<Action> {
  return call(api.PATCH('/orgs/{orgId}/actions/{id}', { params: { path: { orgId, id } }, body }));
}

/** Refreshes every list an action or group change can affect (grants re-render on the server). */
export function invalidateActions(qc: QueryClient, orgId: string) {
  return Promise.all([qc.invalidateQueries({ queryKey: ['actions', orgId] }), qc.invalidateQueries({ queryKey: ['action-groups', orgId] }), invalidateGrants(qc, orgId)]);
}

export function useDeleteAction(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/actions/{id}', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Action deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['actions', orgId] }),
  });
}

export const actionGroupsQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['action-groups', orgId],
    queryFn: async () => (await call(api.GET('/orgs/{orgId}/action-groups', { params: { path: { orgId } } }))).items,
  });

export function useSaveActionGroup(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: ActionGroupInput }) =>
      id
        ? call(api.PATCH('/orgs/{orgId}/action-groups/{id}', { params: { path: { orgId, id } }, body }))
        : call(api.POST('/orgs/{orgId}/action-groups', { params: { path: { orgId } }, body })),
    meta: { silent: true, success: 'Action group saved' },
    onSuccess: () => invalidateActions(qc, orgId),
  });
}

export function useDeleteActionGroup(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/action-groups/{id}', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Action group deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['action-groups', orgId] }),
  });
}

export const targetHookRunsInfinite = (orgId: string, targetId: string) =>
  infiniteQueryOptions({
    queryKey: ['hook-runs', orgId, 'target', targetId],
    queryFn: ({ pageParam }) =>
      call(api.GET('/orgs/{orgId}/deploy-targets/{id}/hook-runs', { params: { path: { orgId, id: targetId }, query: { limit: 50, cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    refetchInterval: firstPagePoll,
  });
