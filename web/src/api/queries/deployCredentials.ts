import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';
import type { DeployCredential, DeployCredentialInput, DeployCredentialUpdate } from '../types';

export const deployCredentialsQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['deploy-credentials', orgId],
    queryFn: () => call(api.GET('/orgs/{orgId}/deploy-credentials', { params: { path: { orgId } } })),
  });

export function useSaveDeployCredential(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: DeployCredentialInput }): Promise<DeployCredential> => {
      if (id) {
        // PUT takes {name, config}: a credential's kind never changes.
        const update: DeployCredentialUpdate = { name: body.name, config: body.config };
        return call(api.PUT('/orgs/{orgId}/deploy-credentials/{id}', { params: { path: { orgId, id } }, body: update }));
      }
      return call(api.POST('/orgs/{orgId}/deploy-credentials', { params: { path: { orgId } }, body }));
    },
    // 422s show inline in the sheet.
    meta: { silent: true, success: 'Credential saved' },
    // The variables hold a typed secret; evict them as soon as the mutation settles.
    gcTime: 0,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deploy-credentials', orgId] }),
  });
}

export function useDeleteDeployCredential(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.DELETE('/orgs/{orgId}/deploy-credentials/{id}', { params: { path: { orgId, id } } })),
    // A 409 (still used) shows inline in ConfirmDestructive.
    meta: { silent: true, success: 'Credential deleted' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deploy-credentials', orgId] }),
  });
}

/** A stored secret's plaintext. A plain call, not a mutation, so the value
 * lives only in the caller's state. */
export async function revealDeployCredentialSecret(orgId: string, id: string, field: string): Promise<string> {
  const r = await call(api.POST('/orgs/{orgId}/deploy-credentials/{id}/reveal', { params: { path: { orgId, id } }, body: { field } }));
  return r.value;
}

export const CREDENTIAL_KIND_LABEL: Record<string, string> = { ssh: 'SSH', password: 'Password', apiKey: 'API key', token: 'Token' };

/** The target fields a saved credential supplies: its public fields and stored secrets. */
export function suppliedFields(c: Pick<DeployCredential, 'config' | 'storedSecrets'>): string[] {
  return [...new Set([...Object.keys(c.config ?? {}), ...(c.storedSecrets ?? [])])];
}
