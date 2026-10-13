import { useMutation } from '@tanstack/react-query';
import { api, call } from '../client';
import type { SshPeekRequest, SshPeekResult } from '../types';

// Reads the host keys an SSH server presents, from the CertForge server (the
// host key input's Fetch). The caller renders both an ok:false result and a
// thrown ApiError inline, as usePeekTls does.
export function usePeekSshHostKey(orgId: string) {
  return useMutation({
    mutationFn: (body: SshPeekRequest): Promise<SshPeekResult> => call(api.POST('/orgs/{orgId}/ssh/peek', { params: { path: { orgId } }, body })),
    meta: { silent: true },
    gcTime: 0,
  });
}
