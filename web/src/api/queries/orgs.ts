import { queryOptions } from '@tanstack/react-query';
import { api, call } from '../client';

// Adaptation (controller ruling, docs/design.md "Settings" table: General
// lists "orgs, sites"): Phase 1A has no /sites endpoint at all (sites are a
// later-phase entity, see design.md's Phase 2 row), so only the read-only
// orgs list is shown here.
export const orgsQuery = queryOptions({
  queryKey: ['orgs'],
  queryFn: async () => (await call(api.GET('/orgs'))).items,
});
