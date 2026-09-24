import { z } from 'zod';

// Adaptation (real API, openapi.yaml `ListSort`): the API's sort parameter
// also accepts `status`/`-status`, in addition to the three fields below.
// No column here is sortable by status (design.md's certificates inventory
// column list has no status sort, and none of the columns wire a `status`
// `meta.sortKey`), so it's left out of this enum.
export const CERT_SORTS = ['name', '-name', 'notAfter', '-notAfter', 'nextRenewAt', '-nextRenewAt'] as const;

export const certListSearch = z.object({
  status: z.enum(['pending', 'active', 'failed', 'expired', 'revoked']).optional().catch(undefined),
  q: z.string().optional().catch(undefined),
  sort: z.enum(CERT_SORTS).optional().catch(undefined),
});
export type CertListSearch = z.infer<typeof certListSearch>;
