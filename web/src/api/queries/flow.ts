import { queryOptions } from '@tanstack/react-query';
import { POLL } from '@/lib/polling';
import { api, call } from '../client';

export const flowQuery = (orgId: string) =>
  queryOptions({
    queryKey: ['flow', orgId] as const,
    queryFn: () => call(api.GET('/orgs/{orgId}/flow', { params: { path: { orgId } } })),
    refetchInterval: POLL.list,
  });
