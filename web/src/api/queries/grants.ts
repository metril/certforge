import { queryOptions, useMutation, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { livePoll } from '@/lib/polling';
import { api, call } from '../client';
import { errorMessage } from '../errors';
import type { Grant, GrantInput, GrantUpdate, ServerGrantInput } from '../types';

export const grantsQuery = (orgId: string, clientId: string) =>
  queryOptions({
    queryKey: ['grants', orgId, clientId],
    queryFn: async () => (await call(api.GET('/orgs/{orgId}/clients/{id}/grants', { params: { path: { orgId, id: clientId } } }))).items,
    // A pending deployment lands within seconds on a connected push client.
    refetchInterval: (q) => livePoll(!!q.state.data?.some((g) => g.deployment?.state === 'pending')),
  });

export const certificateDeploymentsQuery = (orgId: string, certId: string) =>
  queryOptions({
    queryKey: ['deployments', orgId, certId],
    queryFn: async () => (await call(api.GET('/orgs/{orgId}/certificates/{id}/deployments', { params: { path: { orgId, id: certId } } }))).items,
    refetchInterval: (q) => livePoll(!!q.state.data?.some((d) => d.deployment.state === 'pending')),
  });

// A server-side deploy target's own grants (runsOn: server); polls only
// while one is still pending (Review Focus: "polling that never stops" —
// T9 "stops polling when settled").
export const targetGrantsQuery = (orgId: string, targetId: string) =>
  queryOptions({
    queryKey: ['grants', orgId, 'target', targetId],
    queryFn: () => call(api.GET('/orgs/{orgId}/deploy-targets/{id}/grants', { params: { path: { orgId, id: targetId } } })),
    refetchInterval: (q) => livePoll(!!q.state.data?.some((g) => g.serverDeployment?.status === 'pending')),
  });

/** Anything that changes a grant moves client counts, deployments and the
 * certificates list's Grants column. */
export async function invalidateGrants(qc: QueryClient, orgId: string): Promise<void> {
  await Promise.all(
    [
      ['grants', orgId],
      ['grants', orgId, 'target'],
      ['deployments', orgId],
      ['clients', orgId],
      ['clients', 'all'],
      ['certs', orgId],
      ['certs', 'all', 'every'],
    ].map((queryKey) => qc.invalidateQueries({ queryKey })),
  );
}

export type GrantBatchResult = { created: Grant[]; failed: { certificateId: string; message: string }[] };

/** One POST per certificate, in order; a failure never stops the rest. */
export async function createGrants(
  orgId: string,
  clientId: string,
  certificateIds: string[],
  rest: Omit<GrantInput, 'certificateId'>,
): Promise<GrantBatchResult> {
  const out: GrantBatchResult = { created: [], failed: [] };
  for (const certificateId of certificateIds) {
    try {
      out.created.push(
        await call(api.POST('/orgs/{orgId}/clients/{id}/grants', { params: { path: { orgId, id: clientId } }, body: { ...rest, certificateId } })),
      );
    } catch (e) {
      out.failed.push({ certificateId, message: errorMessage(e) });
    }
  }
  return out;
}

export function useCreateGrants(orgId: string, clientId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ certificateIds, rest }: { certificateIds: string[]; rest: Omit<GrantInput, 'certificateId'> }) =>
      createGrants(orgId, clientId, certificateIds, rest),
    meta: { silent: true },
    onSettled: () => invalidateGrants(qc, orgId),
  });
}

export function useCreateServerGrant(orgId: string, targetId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ServerGrantInput) =>
      call(api.POST('/orgs/{orgId}/deploy-targets/{id}/grants', { params: { path: { orgId, id: targetId } }, body })),
    meta: { silent: true, success: 'Grant created' },
    onSuccess: () => invalidateGrants(qc, orgId),
  });
}

export function useUpdateGrant(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: GrantUpdate }) => call(api.PATCH('/orgs/{orgId}/grants/{id}', { params: { path: { orgId, id } }, body })),
    meta: { silent: true, success: 'Grant saved' },
    onSuccess: () => invalidateGrants(qc, orgId),
  });
}

export function useDeleteGrant(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    // Grant delete is asynchronous (3a-facts.md): it stays "removal-pending"
    // until the agent confirms, unless force=true hard-deletes it now.
    mutationFn: ({ id, force }: { id: string; force?: boolean }) =>
      call(api.DELETE('/orgs/{orgId}/grants/{id}', { params: { path: { orgId, id }, query: force ? { force: true } : undefined } })),
    meta: { silent: true, success: 'Grant removed' },
    onSuccess: () => invalidateGrants(qc, orgId),
  });
}

export function useRedeployGrant(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.POST('/orgs/{orgId}/grants/{id}/redeploy', { params: { path: { orgId, id } } })),
    meta: { success: 'Redeploy queued' },
    onSuccess: () => invalidateGrants(qc, orgId),
  });
}
