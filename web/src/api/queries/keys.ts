import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, call } from '../client';
import type { KeysStatus } from '../types';

export const keysStatusQuery = queryOptions({
  queryKey: ['keys-status'],
  queryFn: () => call(api.GET('/keys/status')),
  // 5 s while a rewrap is running, otherwise not at all (Review Focus:
  // "polling that never stops" — T7 "polls only while running").
  refetchInterval: (q) => (q.state.data?.rewrap?.running ? 5000 : false),
});

export function useStartRewrap() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => call(api.POST('/keys/rewrap')),
    meta: { success: 'Rewrap started' },
    onSuccess: (data: KeysStatus) => qc.setQueryData(['keys-status'], data),
  });
}
