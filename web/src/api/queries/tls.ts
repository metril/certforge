import { useMutation } from '@tanstack/react-query';
import { api, call } from '../client';
import type { TlsPeekRequest, TlsPeekResult } from '../types';

// Reads the chain a server presents, from the CertForge server (the CA
// bundle input's Fetch). The caller renders both an ok:false result and a
// thrown ApiError inline, as useProbeAdcs does.
export function usePeekTls(orgId: string) {
  return useMutation({
    mutationFn: (body: TlsPeekRequest): Promise<TlsPeekResult> => call(api.POST('/orgs/{orgId}/tls/peek', { params: { path: { orgId } }, body })),
    meta: { silent: true },
    gcTime: 0,
  });
}
