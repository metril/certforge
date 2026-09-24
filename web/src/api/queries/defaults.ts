import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';
import type { IssuanceDefaults } from '../types';

export const orgDefaultsQuery = (orgId: string) =>
  queryOptions({ queryKey: ['defaults', orgId], queryFn: () => call(api.GET('/orgs/{orgId}/issuance-defaults', { params: { path: { orgId } } })) });

// Adaptation (preflight A8, controller ruling): the org tab's per-field
// source badge must come from this endpoint, never inferred by comparing
// the raw global/org values — GET /settings/issuance_defaults fills in the
// built-in defaults for display even when nothing has actually been saved
// at the global level, so a raw-value comparison would mislabel a
// 'default' field as 'global'.
export const effectiveDefaultsQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['defaults', orgId, 'effective'],
    queryFn: () => call(api.GET('/orgs/{orgId}/issuance-defaults/effective', { params: { path: { orgId } } })),
  });

export function useSaveOrgDefaults(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: IssuanceDefaults) => call(api.PUT('/orgs/{orgId}/issuance-defaults', { params: { path: { orgId } }, body })),
    // A 422 (dangling caId/accountId) is mapped to its field and shown
    // inline (controller ruling); a toast on top would be redundant.
    meta: { silent: true, success: 'Org defaults saved' },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['defaults', orgId] });
      await qc.invalidateQueries({ queryKey: ['certs', orgId] });
    },
  });
}
