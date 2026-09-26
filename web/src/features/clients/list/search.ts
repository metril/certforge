import { z } from 'zod';

export const CLIENT_SORTS = ['name', '-name', 'lastSeen', '-lastSeen', 'status', '-status'] as const;
export const CLIENT_STATUS_LABEL = { pending: 'Pending', active: 'Active', revoked: 'Revoked' } as const;

// Every field falls back to "absent" when a hand-edited URL is invalid.
export const clientListSearch = z.object({
  status: z.enum(['pending', 'active', 'revoked']).optional().catch(undefined),
  site: z
    .string()
    .regex(/^[\w-]{1,64}$/)
    .optional()
    .catch(undefined),
  q: z.string().min(1).max(200).optional().catch(undefined),
  sort: z.enum(CLIENT_SORTS).optional().catch(undefined),
});
export type ClientListSearch = z.infer<typeof clientListSearch>;
