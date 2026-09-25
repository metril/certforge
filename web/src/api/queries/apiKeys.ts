import { queryOptions } from '@tanstack/react-query';
import { api, call } from '../client';

// Minimal read query for Task 4's BindingSheet (apikey subject picker).
// Task 6 owns the API keys tab proper and extends this file with
// useCreateApiKey/useRevokeApiKey mutations per the 2A spec.
export const apiKeysQuery = (orgId?: string) =>
  queryOptions({
    queryKey: ['api-keys', orgId ?? 'all'],
    queryFn: async () => (await call(api.GET('/api-keys', { params: { query: orgId ? { orgId } : {} } }))).items,
  });
