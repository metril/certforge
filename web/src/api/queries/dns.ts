import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';
import type { DnsCredential, DnsCredentialInput, DnsCredentialTestResult, DnsCredentialUpdate } from '../types';

export const metaSchemasQuery = queryOptions({ queryKey: ['meta-schemas'], queryFn: () => call(api.GET('/meta/schemas')), staleTime: Infinity });

export const dnsCredentialsQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['dns', orgId],
    queryFn: () => call(api.GET('/orgs/{orgId}/dns-credentials', { params: { path: { orgId } } })),
  });

export function useSaveCredential(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: DnsCredentialInput }): Promise<DnsCredential> => {
      if (id) {
        // Adaptation (preflight A17): PUT takes DNSCredentialUpdate {name, config}
        // — no providerCode (a credential's provider never changes on edit).
        const update: DnsCredentialUpdate = { name: body.name, config: body.config };
        return call(api.PUT('/orgs/{orgId}/dns-credentials/{id}', { params: { path: { orgId, id } }, body: update }));
      }
      return call(api.POST('/orgs/{orgId}/dns-credentials', { params: { path: { orgId } }, body }));
    },
    // Fix round pattern (matches useSaveCa): 422s are shown inline next to the
    // form (CredentialSheet), so a toast on top would be redundant/out of context.
    meta: { silent: true, success: 'Credential saved' },
    // Fix round 1 (Important): the mutation's own variables (a typed secret,
    // for create or replace) sit in the MutationCache until gc; the default
    // 5-minute gcTime otherwise keeps a plaintext secret in memory well past
    // the request. Evict immediately once settled.
    gcTime: 0,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dns', orgId] }),
  });
}

export function useDeleteCredential(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/dns-credentials/{id}', { params: { path: { orgId, id } } })),
    // 409 (still referenced) is shown inline in ConfirmDestructive; silent avoids a duplicate toast.
    meta: { silent: true, success: 'Credential deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dns', orgId] }),
  });
}

export function useTestCredential(orgId: string) {
  return useMutation({
    mutationFn: ({ id, zone }: { id: string; zone: string }): Promise<DnsCredentialTestResult> =>
      call(api.POST('/orgs/{orgId}/dns-credentials/{id}/test', { params: { path: { orgId, id } }, body: { zone } })),
    // TestCredentialDialog renders both a 200 ok:false and a thrown ApiError
    // (incl. a 503 + Retry-After from the test semaphore) inline itself.
    meta: { silent: true },
    // Fix round 1: symmetry with useSaveCredential's gcTime — no mutation
    // touching credential data lingers in the MutationCache.
    gcTime: 0,
  });
}

/** Returns a stored secret's plaintext. Deliberately uncached and never
 * invalidating: the value lives only in the caller's state until hidden. */
export function useRevealCredentialSecret(orgId: string) {
  return useMutation({
    mutationFn: async ({ id, field }: { id: string; field: string }): Promise<string> => {
      const r = await call(api.POST('/orgs/{orgId}/dns-credentials/{id}/reveal', { params: { path: { orgId, id } }, body: { field } }));
      return r.value;
    },
    // SecretInput shows the error itself (tooltip); a toast would be redundant.
    meta: { silent: true },
    gcTime: 0,
  });
}
