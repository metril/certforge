import { queryOptions } from '@tanstack/react-query';
import { api, call } from '../client';
import type { RateLimitName } from '../types';

export const rateLedgerQuery = (orgId: string, caId: string, certId?: string) =>
  queryOptions({
    queryKey: ['rate-ledger', orgId, caId, certId ?? null],
    queryFn: () =>
      call(api.GET('/orgs/{orgId}/rate-ledger', { params: { path: { orgId }, query: { ca: caId, certificate: certId } } })),
    staleTime: 30_000,
  });

export const RATE_LIMIT_LABEL: Record<RateLimitName, string> = {
  certsPerRegisteredDomainPerWeek: 'Certificates per domain, 7 days',
  duplicateCertsPerWeek: 'Duplicate certificates, 7 days',
  failedValidationsPerHour: 'Failed validations, 1 hour',
  newOrdersPer3Hours: 'New orders, 3 hours',
};
