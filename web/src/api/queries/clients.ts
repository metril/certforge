import { infiniteQueryOptions, queryOptions, useMutation, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { livePoll, POLL } from '@/lib/polling';
import { api, call } from '../client';
import type { Client, ClientInput, ClientStatus, ClientUpdate } from '../types';

export type ClientListQuery = { status?: ClientStatus; site?: string; q?: string; sort?: string };

/** orgId is an org id, or 'all' for the All orgs view. */
export const clientListKey = (orgId: string, s: ClientListQuery) => ['clients', orgId, 'list', s] as const;

export const clientsInfinite = (orgId: string, s: ClientListQuery) =>
  infiniteQueryOptions({
    queryKey: clientListKey(orgId, s),
    queryFn: ({ pageParam }) =>
      call(
        api.GET('/orgs/{orgId}/clients', {
          params: { path: { orgId }, query: { status: s.status, site: s.site, q: s.q, sort: s.sort, limit: 100, cursor: pageParam } },
        }),
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    refetchInterval: POLL.list,
  });

export const allOrgsClientsInfinite = (s: ClientListQuery) =>
  infiniteQueryOptions({
    queryKey: clientListKey('all', s),
    queryFn: ({ pageParam }) => call(api.GET('/clients', { params: { query: { status: s.status, q: s.q, sort: s.sort, limit: 100, cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    refetchInterval: POLL.list,
  });

const PAGE = 200;
const MAX_PAGES = 50;

export type EveryPage<T> = { items: T[]; truncated: boolean };

/** truncated is true when the 50 x 200 cap stopped the walk before the
 * server ran out of pages (a genuinely large org, not the common case). */
async function everyPage(get: (cursor?: string) => Promise<{ items: Client[]; nextCursor?: string | null }>): Promise<EveryPage<Client>> {
  const out: Client[] = [];
  let cursor: string | undefined;
  let truncated = false;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await get(cursor);
    out.push(...page.items);
    if (!page.nextCursor) break;
    cursor = page.nextCursor;
    if (i === MAX_PAGES - 1) truncated = true;
  }
  return { items: out, truncated };
}

/** Every client in the org, or in every readable org when orgId is 'all'
 * (lib/org.ts's ALL_ORGS.id): Overview's attention queue, the palette. */
export const allClientsQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['clients', orgId, 'all'],
    queryFn: () =>
      everyPage((cursor) =>
        orgId === 'all'
          ? call(api.GET('/clients', { params: { query: { limit: PAGE, cursor } } }))
          : call(api.GET('/orgs/{orgId}/clients', { params: { path: { orgId }, query: { limit: PAGE, cursor } } })),
      ),
    refetchInterval: POLL.list,
  });

export const clientQuery = (orgId: string, id: string) =>
  queryOptions({
    queryKey: ['clients', orgId, 'one', id],
    queryFn: () => call(api.GET('/orgs/{orgId}/clients/{id}', { params: { path: { orgId, id } } })),
    // 2 s while the agent has not enrolled yet (a fresh or re-issued token).
    refetchInterval: (q) => livePoll(q.state.data?.status === 'pending'),
    staleTime: 0,
  });

function invalidateClients(qc: QueryClient, orgId: string) {
  return Promise.all([qc.invalidateQueries({ queryKey: ['clients', orgId] }), qc.invalidateQueries({ queryKey: ['clients', 'all'] })]);
}

// Revoking or deleting a client also moves its grants (hard-deleted or
// left removal-pending, 3a-facts.md), their deployments, and the
// certificates list's Grants column.
function invalidateClientAndGrants(qc: QueryClient, orgId: string) {
  return Promise.all([
    invalidateClients(qc, orgId),
    qc.invalidateQueries({ queryKey: ['grants', orgId] }),
    qc.invalidateQueries({ queryKey: ['deployments', orgId] }),
    qc.invalidateQueries({ queryKey: ['certs', orgId] }),
  ]);
}

export function useCreateClient(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ClientInput) => call(api.POST('/orgs/{orgId}/clients', { params: { path: { orgId } }, body })),
    // The response holds the one-time token: drop it from the mutation
    // cache as soon as nothing observes it (the page also calls reset()).
    gcTime: 0,
    meta: { silent: true },
    onSuccess: () => invalidateClients(qc, orgId),
  });
}

export function useUpdateClient(orgId: string, id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ClientUpdate) => call(api.PATCH('/orgs/{orgId}/clients/{id}', { params: { path: { orgId, id } }, body })),
    meta: { silent: true, success: 'Client saved' },
    onSuccess: () => invalidateClients(qc, orgId),
  });
}

export function useRevokeClient(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.POST('/orgs/{orgId}/clients/{id}/revoke', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Client revoked' },
    onSuccess: () => invalidateClientAndGrants(qc, orgId),
  });
}

export function useReenrollClient(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.POST('/orgs/{orgId}/clients/{id}/reenroll', { params: { path: { orgId, id } } })),
    gcTime: 0,
    meta: { silent: true },
    onSuccess: () => invalidateClients(qc, orgId),
  });
}

export function useDeleteClient(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/clients/{id}', { params: { path: { orgId, id } } })),
    meta: { silent: true, success: 'Client deleted' },
    onSuccess: () => invalidateClientAndGrants(qc, orgId),
  });
}

export const hookRunsInfinite = (orgId: string, clientId: string) =>
  infiniteQueryOptions({
    queryKey: ['hook-runs', orgId, clientId],
    queryFn: ({ pageParam }) =>
      call(api.GET('/orgs/{orgId}/clients/{id}/hook-runs', { params: { path: { orgId, id: clientId }, query: { limit: 50, cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    refetchInterval: POLL.list,
  });
