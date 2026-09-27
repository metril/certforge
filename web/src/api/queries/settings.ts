import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';

export type SectionId = 'general' | 'issuance_defaults' | 'backup' | 'authentication' | 'agents' | 'issuance';

export const settingsQuery = (section: SectionId) =>
  queryOptions({ queryKey: ['settings', section], queryFn: () => call(api.GET('/settings/{section}', { params: { path: { section } } })) });

// `silent` lets a richer form (Issuance defaults' Global tab, which maps a
// 422 to a field inline, controller ruling) suppress the default toast the
// way useSaveCa/useSaveCredential already do; the plain schema-driven
// sections (General, Backup) have no inline mapping, so they keep it.
export function useSaveSettings(section: SectionId, opts: { silent?: boolean } = {}) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (value: Record<string, unknown>) => call(api.PUT('/settings/{section}', { params: { path: { section } }, body: value })),
    meta: { silent: opts.silent, success: 'Settings saved' },
    // Review fix round 1 (#6): awaited, like useSaveOrgDefaults's own
    // onSuccess, so the mutation stays "pending" through the refetch and a
    // caller that awaits mutateAsync doesn't see a flash of the old value
    // before the invalidated query lands.
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['settings', section] });
      // A global issuance_defaults change can move every org's effective
      // values between 'global' and 'default' sources (A8), and any cert
      // that inherits it — invalidate both, the same way a per-org save
      // already invalidates ['defaults', orgId] and ['certs', orgId].
      if (section === 'issuance_defaults') {
        await qc.invalidateQueries({ queryKey: ['defaults'] });
        await qc.invalidateQueries({ queryKey: ['certs'] });
      }
      // A saved OIDC change (enabled, issuer, clientId, ...) can flip
      // whether the login page offers single sign-on; a saved General
      // change can move baseUrl, which drives the callback URL
      // Authentication shows (fix round 1, Take now #5) — either way
      // `['auth-methods']` (`AuthMethods.oidcCallbackUrl`) is now stale.
      if (section === 'authentication' || section === 'general') {
        await qc.invalidateQueries({ queryKey: ['auth-methods'] });
      }
      // Listener names and the agent URL re-issue the listener certificate.
      if (section === 'agents') await qc.invalidateQueries({ queryKey: ['agent-cas'] });
    },
  });
}

/** Tests the OIDC issuer currently in the form (admin only), fetching
 * discovery and JWKS without saving anything. */
export function useTestAuthentication() {
  return useMutation({
    mutationFn: (issuer: string) => call(api.POST('/settings/authentication/test', { body: { issuer } })),
    meta: { silent: true },
  });
}
