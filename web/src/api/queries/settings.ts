import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';

export type SectionId = 'general' | 'issuance_defaults' | 'backup';

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
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings', section] });
      // A global issuance_defaults change can move every org's effective
      // values between 'global' and 'default' sources (A8): invalidate the
      // per-org caches too, not just this section's own.
      if (section === 'issuance_defaults') void qc.invalidateQueries({ queryKey: ['defaults'] });
    },
  });
}
