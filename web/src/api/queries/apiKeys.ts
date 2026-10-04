import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { POLL } from '@/lib/polling';
import { api, call } from '../client';
import type { ApiKeyInput } from '../types';

export const apiKeysQuery = (orgId?: string) =>
  queryOptions({
    queryKey: ['api-keys', orgId ?? 'all'],
    queryFn: () => call(api.GET('/api-keys', { params: { query: orgId ? { orgId } : {} } })),
    // The list and the creation policy share one response; consumers pick a part.
    select: (d) => d.items,
    refetchInterval: POLL.list,
  });

export function useCreateApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ApiKeyInput) => call(api.POST('/api-keys', { body })),
    meta: { silent: true },
    // The response carries the one-time token; never keep it after the dialog.
    gcTime: 0,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
  });
}

export function useRevokeApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/api-keys/{id}', { params: { path: { id } } })),
    meta: { silent: true, success: 'API key revoked' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
  });
}

/** The server's key limits, from the same cached response as the key list. */
export const apiKeyPolicyQuery = () => queryOptions({ ...apiKeysQuery(), select: (d) => d.policy });
