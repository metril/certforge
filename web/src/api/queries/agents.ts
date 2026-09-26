import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query';
import { POLL } from '@/lib/polling';
import { api, call } from '../client';

export const agentCAsQuery = queryOptions({
  queryKey: ['agent-cas'],
  queryFn: () => call(api.GET('/agents/ca')),
  refetchInterval: POLL.list,
});

export function useRotateAgentCA() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => call(api.POST('/agents/ca/rotate')),
    meta: { silent: true, success: 'Agent CA rotated' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agent-cas'] }),
  });
}

export function useRetireAgentCA() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => call(api.POST('/agents/ca/{id}/retire', { params: { path: { id } } })),
    meta: { silent: true, success: 'Agent CA retired' },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agent-cas'] }),
  });
}
